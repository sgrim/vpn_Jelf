/*
 * Copyright © 2018-2026 Diego Fernando Mayor Rojas. Todos los derechos reservados.
 *
 * Este archivo es parte de jelf. Software propietario:
 * queda prohibida su copia, uso, modificación o distribución
 * sin autorización expresa y por escrito del autor. Ver el archivo LICENSE.
 */
/*
 * Rand.java - Bytes al azar del sistema (/dev/urandom). Si no se puede leer, el programa NO sigue con azar flojo: se detiene (RIESGOS.md R-S07).
 */

public final class Rand {
  static FileInputStream dev;

  public static byte[] bytes(int n) {
    byte[] b = new byte[n];
    fill(b, 0, n);
    return b;
  }

  public static void fill(byte[] b, int off, int n) {
    if (dev == null) dev = new FileInputStream("/dev/urandom");
    int got = 0;
    while (got < n) {
      int r = dev.read(b, off + got, n - got);
      if (r <= 0) {
        System.out.println("jvpn: no se puede leer /dev/urandom; no se continúa sin azar del sistema");
        System.exit(1);
      }
      got += r;
    }
  }
}
