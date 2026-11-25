/*
 * Copyright © 2018-2026 Diego Fernando Mayor Rojas. Todos los derechos reservados.
 *
 * Este archivo es parte de jelf. Software propietario:
 * queda prohibida su copia, uso, modificación o distribución
 * sin autorización expresa y por escrito del autor. Ver el archivo LICENSE.
 */
/*
 * Gso.java - Lo que el núcleo deja a medias en una TUN abierta con virtio_net_hdr (Tun.open con vnet y Tun.setOffload):
 *   (1) un segmento TCP de IPv4 de hasta 64 KB sin partir (gso_type = 1): se parte en paquetes de gso_size bytes de datos, cada uno con su largo, su identificador, su número de secuencia, sus
 *       banderas (FIN y PSH solo en el último) y sus dos sumas de control (IP y TCP) recalculadas;
 *   (2) un paquete suelto con la suma de control sin completar (flags = 1, gso_type = 0): se completa.
 * Todo lo demás (otro tipo de GSO, cabeceras que no cuadran, largos imposibles) se descarta: la entrada viene del núcleo local pero se trata como hostil, y ningún campo decide un acceso fuera del búfer.
 * Uso: begin(búfer leído, n) y luego next(salida) hasta que devuelva 0; cada next deja UN paquete IP completo en salida[0..largo).
 * Las sumas se hacen con palabras de 32 bits little-endian (la suma de complemento a uno no depende del orden de los bytes salvo por un intercambio final, RFC 1071 §2).
 */

public final class Gso {
  public static final int HDR = 10; // = Tun.VNET_HDR
  static final int NEEDS_CSUM = 1;
  static final int TCPV4 = 1;

  byte[] in;
  int end; // fin de los datos en in
  int kind; // 0 = nada, 1 = un solo paquete, 2 = segmentos TCP
  int csumStart;
  int csumField;
  boolean needsCsum;
  int ihl;
  int hdrLen;
  int mss;
  int cur; // dónde sigue el siguiente trozo de datos en in
  int seq0;
  int id0;
  int count; // segmentos ya entregados
  boolean done;

  /** Suma de palabras de 32 bits little-endian de b[off..off+n), con el resto relleno de ceros. Solo para rangos ya comprobados. */
  static long raw(byte[] b, int off, int n) {
    long s = 0;
    int i = off;
    int e = off + (n & ~3);
    for (; i < e; i += 4) s += Bytes.unsafeGetInt(b, i) & 0xffffffffL;
    int r = off + n - i;
    if (r > 0) {
      long v = 0;
      for (int j = 0; j < r; j++) v |= (b[i + j] & 255L) << (8 * j);
      s += v;
    }
    return s;
  }

  static int fold(long s) {
    while ((s >>> 16) != 0) s = (s & 0xffff) + (s >>> 16);
    return (int) s;
  }

  static int swap16(int v) {
    return ((v & 255) << 8) | ((v >>> 8) & 255);
  }

  /** La suma de complemento a uno (SIN complementar, en el orden de red) de b[off..off+n), más un valor inicial en el orden de red. */
  static int sum(byte[] b, int off, int n, int initial) {
    return fold(initial + swap16(fold(raw(b, off, n))));
  }

  static void put16(byte[] b, int off, int v) {
    b[off] = (byte) (v >> 8);
    b[off + 1] = (byte) v;
  }

  static int get16(byte[] b, int off) {
    return ((b[off] & 255) << 8) | (b[off + 1] & 255);
  }

  static int getLE16(byte[] b, int off) {
    return (b[off] & 255) | ((b[off + 1] & 255) << 8);
  }

  /** Mira la cabecera virtio_net_hdr y lo que sigue. Devuelve false si hay que descartar el paquete (nada se ha entregado). */
  public boolean begin(byte[] b, int n) {
    kind = 0;
    done = true;
    if (n < HDR + 20 || n > b.length) return false;
    int flags = b[0] & 255;
    int type = b[1] & 255;
    in = b;
    end = n;
    needsCsum = (flags & NEEDS_CSUM) != 0;
    if (type == 0) {
      if (needsCsum) {
        csumStart = getLE16(b, 6);
        csumField = csumStart + getLE16(b, 8);
        if (csumStart > n - HDR || csumField + 2 > n - HDR) return false;
      }
      kind = 1;
      done = false;
      return true;
    }
    if (type != TCPV4) return false;
    hdrLen = getLE16(b, 2);
    mss = getLE16(b, 4);
    if (mss < 1 || hdrLen < 40 || HDR + hdrLen > n) return false;
    int p = HDR;
    if ((b[p] >> 4) != 4 || (b[p + 9] & 255) != 6) return false;
    ihl = (b[p] & 15) * 4;
    if (ihl < 20 || ihl + 20 > hdrLen) return false;
    int doff = ((b[p + ihl + 12] & 255) >> 4) * 4;
    if (doff < 20 || ihl + doff != hdrLen) return false;
    if (hdrLen + mss > 65535) return false;
    int tl = get16(b, p + 2);
    if (tl != 0 && tl < n - HDR) end = HDR + tl; // sobra al final: se ignora
    if (end < HDR + hdrLen) return false;
    cur = HDR + hdrLen;
    seq0 = Bytes.getIntBE(b, p + ihl + 4);
    id0 = get16(b, p + 4);
    count = 0;
    kind = 2;
    done = false;
    return true;
  }

  /** El siguiente paquete en out[0..), con su largo, o 0 si ya no hay más. out debe medir al menos 65535 bytes. */
  public int next(byte[] out) {
    if (done) return 0;
    if (kind == 1) {
      done = true;
      int len = end - HDR;
      for (int i = 0; i < len; i++) out[i] = in[HDR + i];
      if (needsCsum) {
        int initial = get16(out, csumField);
        put16(out, csumField, 0);
        int c = ~sum(out, csumStart, len - csumStart, initial) & 0xffff;
        if (c == 0 && len > 9 && (out[9] & 255) == 17) c = 0xffff; // UDP: una suma cero significa «sin suma»
        put16(out, csumField, c);
      }
      return len;
    }
    int len = end - cur;
    if (len > mss) len = mss;
    boolean last = cur + len >= end;
    int total = hdrLen + len;
    for (int i = 0; i < hdrLen; i++) out[i] = in[HDR + i];
    for (int i = 0; i < len; i++) out[hdrLen + i] = in[cur + i];
    put16(out, 2, total);
    put16(out, 4, (id0 + count) & 0xffff);
    put16(out, 10, 0);
    put16(out, 10, ~sum(out, 0, ihl, 0) & 0xffff);
    int t = ihl;
    Bytes.putIntBE(out, t + 4, seq0 + (cur - (HDR + hdrLen)));
    if (!last) out[t + 13] &= ~(1 | 8); // FIN y PSH solo en el último
    put16(out, t + 16, 0);
    int tcpLen = total - ihl;
    int pseudo = fold(((long) get16(out, 12)) + get16(out, 14) + get16(out, 16) + get16(out, 18) + 6 + tcpLen);
    put16(out, t + 16, ~sum(out, t, tcpLen, pseudo) & 0xffff);
    cur += len;
    count++;
    if (last) done = true;
    return total;
  }
}
