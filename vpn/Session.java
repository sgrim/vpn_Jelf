/*
 * Copyright © 2018-2026 Diego Fernando Mayor Rojas. Todos los derechos reservados.
 *
 * Este archivo es parte de jelf. Software propietario:
 * queda prohibida su copia, uso, modificación o distribución
 * sin autorización expresa y por escrito del autor. Ver el archivo LICENSE.
 */
/*
 * Session.java - Las claves de transporte de un par y los mensajes de DATOS de WireGuard (tipo 4): contador de 64 bits en el nonce, relleno a múltiplo de 16, ventana antirrepetición de 2048 y los
 * límites de mensajes. Un mensaje vacío (solo la etiqueta) es un keepalive. open comprueba la etiqueta ANTES de tocar la ventana (un paquete falso no puede mover la ventana).
 */

public final class Session {
  public static final int WINDOW = 2048;
  /** Tras este número de mensajes la sesión no se usa más (REJECT_AFTER_MESSAGES = 2^64 − 2^13 − 1; aquí, lo que cabe sin signo dudoso). */
  public static final long REJECT_AFTER = 0x7fffffffffffff00L;

  public final byte[] sendKey;
  public final byte[] recvKey;
  public final int localIndex;
  public final int remoteIndex;
  long sendCounter;
  long highest = -1;
  final long[] bitmap = new long[WINDOW / 64];
  public boolean initiator;

  public Session(byte[] sendKey, byte[] recvKey, int localIndex, int remoteIndex, boolean initiator) {
    this.sendKey = sendKey;
    this.recvKey = recvKey;
    this.localIndex = localIndex;
    this.remoteIndex = remoteIndex;
    this.initiator = initiator;
  }

  /** Cifra un paquete IP (len bytes de p) en un mensaje de datos; null si la sesión agotó sus mensajes. */
  public byte[] seal(byte[] p, int len) {
    if (sendCounter >= REJECT_AFTER || sendCounter < 0) return null;
    int padded = (len + 15) & ~15;
    byte[] pt = new byte[padded];
    for (int i = 0; i < len; i++) pt[i] = p[i];
    byte[] ct = Wg.seal(sendKey, sendCounter, new byte[0], pt);
    byte[] m = new byte[Wg.DATA_HEADER + ct.length];
    m[0] = 4;
    Wg.putLE32(m, 4, remoteIndex);
    Wg.putLE64(m, 8, sendCounter);
    Wg.copy(ct, 0, m, Wg.DATA_HEADER, ct.length);
    sendCounter++;
    return m;
  }

  /** El contenido (con su relleno) de un mensaje de datos, o null si no es para esta sesión, la etiqueta no vale o se repite. */
  public byte[] open(byte[] m, int len) {
    if (len < Wg.DATA_HEADER + Wg.TAG || m[0] != 4 || m[1] != 0 || m[2] != 0 || m[3] != 0) return null;
    if (Wg.getLE32(m, 4) != localIndex) return null;
    long ctr = Wg.getLE64(m, 8);
    if (ctr < 0 || ctr >= REJECT_AFTER) return null;
    if (!fresh(ctr)) return null;
    byte[] pt = Wg.open(recvKey, ctr, new byte[0], m, Wg.DATA_HEADER, len - Wg.DATA_HEADER);
    if (pt == null) return null;
    mark(ctr);
    return pt;
  }

  static final byte[] NO_AAD = new byte[0];
  final byte[] nonceBuf = new byte[12];

  /**
   * Como seal pero SIN reservar: arma el mensaje de datos de p[0..len) en out (que debe medir al menos 16 + relleno + 16 bytes; una de 65 664 sirve para cualquier paquete) y devuelve su largo, o -1 si la sesión
   * agotó sus mensajes o no cabe. El paquete se cifra en el sitio dentro de out.
   */
  public int sealInto(byte[] p, int len, byte[] out) {
    if (sendCounter >= REJECT_AFTER || sendCounter < 0) return -1;
    int padded = (len + 15) & ~15;
    int total = Wg.DATA_HEADER + padded + Wg.TAG;
    if (len < 0 || total > out.length) return -1;
    out[0] = 4;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    Wg.putLE32(out, 4, remoteIndex);
    Wg.putLE64(out, 8, sendCounter);
    for (int i = 0; i < len; i++) out[Wg.DATA_HEADER + i] = p[i];
    for (int i = len; i < padded; i++) out[Wg.DATA_HEADER + i] = 0;
    for (int i = 0; i < 4; i++) nonceBuf[i] = 0;
    Wg.putLE64(nonceBuf, 4, sendCounter);
    ChaCha20Poly1305.sealInto(sendKey, nonceBuf, NO_AAD, out, Wg.DATA_HEADER, padded, out, Wg.DATA_HEADER);
    sendCounter++;
    return total;
  }

  /**
   * Como open pero SIN reservar: descifra el mensaje m[0..len) en out[0..) y devuelve el largo del contenido (con su relleno), o -1 si no es para esta sesión, la etiqueta no vale o se repite.
   * La etiqueta se comprueba ANTES de tocar la ventana y de escribir en out.
   */
  public int openInto(byte[] m, int len, byte[] out) {
    if (len < Wg.DATA_HEADER + Wg.TAG || m[0] != 4 || m[1] != 0 || m[2] != 0 || m[3] != 0) return -1;
    if (Wg.getLE32(m, 4) != localIndex) return -1;
    long ctr = Wg.getLE64(m, 8);
    if (ctr < 0 || ctr >= REJECT_AFTER) return -1;
    if (!fresh(ctr)) return -1;
    for (int i = 0; i < 4; i++) nonceBuf[i] = 0;
    Wg.putLE64(nonceBuf, 4, ctr);
    int n = ChaCha20Poly1305.openInto(recvKey, nonceBuf, NO_AAD, m, Wg.DATA_HEADER, len - Wg.DATA_HEADER, out, 0);
    if (n < 0) return -1;
    mark(ctr);
    return n;
  }

  boolean fresh(long ctr) {
    if (ctr > highest) return true;
    if (highest - ctr >= WINDOW) return false;
    int i = (int) (ctr % WINDOW);
    return (bitmap[i >> 6] & (1L << (i & 63))) == 0;
  }

  void mark(long ctr) {
    if (ctr > highest) {
      long gap = ctr - highest;
      if (gap >= WINDOW) {
        for (int i = 0; i < bitmap.length; i++) bitmap[i] = 0;
      } else {
        for (long c = highest + 1; c <= ctr; c++) {
          int j = (int) (c % WINDOW);
          bitmap[j >> 6] &= ~(1L << (j & 63));
        }
      }
      highest = ctr;
    }
    int i = (int) (ctr % WINDOW);
    bitmap[i >> 6] |= 1L << (i & 63);
  }
}
