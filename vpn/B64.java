/*
 * Copyright © 2018-2026 Diego Fernando Mayor Rojas. Todos los derechos reservados.
 *
 * Este archivo es parte de jelf. Software propietario:
 * queda prohibida su copia, uso, modificación o distribución
 * sin autorización expresa y por escrito del autor. Ver el archivo LICENSE.
 */
/*
 * B64.java - Base64 (con relleno) para las claves de WireGuard, que son 32 bytes en base64 de 44 caracteres.
 */

public final class B64 {
  static final String A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  public static String encode(byte[] b) {
    StringBuilder s = new StringBuilder();
    int i = 0;
    for (; i + 2 < b.length; i += 3) {
      int v = ((b[i] & 255) << 16) | ((b[i + 1] & 255) << 8) | (b[i + 2] & 255);
      s.append(A.charAt(v >> 18)).append(A.charAt((v >> 12) & 63)).append(A.charAt((v >> 6) & 63)).append(A.charAt(v & 63));
    }
    int rest = b.length - i;
    if (rest == 1) {
      int v = (b[i] & 255) << 16;
      s.append(A.charAt(v >> 18)).append(A.charAt((v >> 12) & 63)).append("==");
    } else if (rest == 2) {
      int v = ((b[i] & 255) << 16) | ((b[i + 1] & 255) << 8);
      s.append(A.charAt(v >> 18)).append(A.charAt((v >> 12) & 63)).append(A.charAt((v >> 6) & 63)).append('=');
    }
    return s.toString();
  }

  /** Una clave de 32 bytes en base64 (44 caracteres con el relleno), o null si no cuadra. Se ignoran los blancos de los extremos. */
  public static byte[] key(String t) {
    t = t.trim();
    if (t.length() != 44 || t.charAt(43) != '=' || t.charAt(42) == '=') return null;
    byte[] out = new byte[33];
    int o = 0;
    for (int i = 0; i < 44; i += 4) {
      int v = 0;
      int n = 0;
      for (int j = 0; j < 4; j++) {
        char c = t.charAt(i + j);
        int k = c == '=' ? 0 : A.indexOf(c);
        if (k < 0) return null;
        v = (v << 6) | k;
        n++;
      }
      out[o++] = (byte) (v >> 16);
      if (o < 33) out[o++] = (byte) (v >> 8);
      if (o < 33) out[o++] = (byte) v;
    }
    byte[] r = new byte[32];
    for (int i = 0; i < 32; i++) r[i] = out[i];
    return r;
  }
}
