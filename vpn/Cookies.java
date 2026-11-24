/*
 * Copyright © 2018-2026 Diego Fernando Mayor Rojas. Todos los derechos reservados.
 *
 * Este archivo es parte de jelf. Software propietario:
 * queda prohibida su copia, uso, modificación o distribución
 * sin autorización expresa y por escrito del autor. Ver el archivo LICENSE.
 */
/*
 * Cookies.java - Lado RESPONDEDOR de las cookies de WireGuard (mitigación de denegación de servicio, whitepaper 5.3): bajo carga el respondedor NO procesa una iniciación sin un MAC2 válido; contesta con
 * una respuesta de cookie (tipo 3, 64 bytes) cifrada con XChaCha20-Poly1305 que solo puede abrir quien recibió el mensaje en esa dirección (IP y puerto de origen). La cookie es MAC(secreto, origen) y el
 * secreto cambia cada 120 s. Con ella el iniciador prueba que ocupa esa dirección; así se puede limitar por origen en vez de gastar curvas elípticas con direcciones falsas.
 */

public final class Cookies {
  public static final long SECRET_LIFE_MS = 120000;
  public static final int REPLY = 64;

  byte[] secret;
  long secretTime = -1;

  /** La cookie de un origen (ip, puerto): MAC de 16 bytes con el secreto vigente, que se renueva a los 120 s. */
  public byte[] cookie(int ip, int port, long now) {
    if (secret == null || secretTime < 0 || now - secretTime >= SECRET_LIFE_MS) {
      secret = Rand.bytes(32);
      secretTime = now;
    }
    byte[] a = new byte[6];
    a[0] = (byte) (ip >>> 24);
    a[1] = (byte) (ip >>> 16);
    a[2] = (byte) (ip >>> 8);
    a[3] = (byte) ip;
    a[4] = (byte) (port >>> 8);
    a[5] = (byte) port;
    return Wg.mac(secret, a, 6);
  }

  /** ¿El MAC2 del mensaje (en mac2Off; cubre msg[0..mac2Off)) es el de la cookie vigente de ese origen? Un MAC2 de ceros nunca vale. */
  public boolean mac2Valid(byte[] m, int mac2Off, int ip, int port, long now) {
    byte[] c = cookie(ip, port, now);
    byte[] e = Wg.mac(c, m, mac2Off);
    int zero = 0;
    for (int i = 0; i < 16; i++) zero |= m[mac2Off + i];
    return Wg.same(e, 0, m, mac2Off, 16) && zero != 0;
  }

  /** La respuesta de cookie para el mensaje m (iniciación o respuesta; su MAC1 va en mac1Off), dirigida a su índice de emisor. */
  public byte[] reply(byte[] m, int mac1Off, int ip, int port, byte[] myPub, long now) {
    byte[] nonce = Rand.bytes(24);
    byte[] aad = new byte[16];
    Wg.copy(m, mac1Off, aad, 0, 16);
    byte[] c = cookie(ip, port, now);
    byte[] ct = XChaCha20Poly1305.seal(Wg.cookieKey(myPub), nonce, aad, c, 0, 16);
    byte[] r = new byte[REPLY];
    r[0] = 3;
    Wg.copy(m, 4, r, 4, 4);
    Wg.copy(nonce, 0, r, 8, 24);
    Wg.copy(ct, 0, r, 32, 32);
    return r;
  }
}
