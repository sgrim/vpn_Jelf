/*
 * Copyright © 2018-2026 Diego Fernando Mayor Rojas. Todos los derechos reservados.
 *
 * Este archivo es parte de jelf. Software propietario:
 * queda prohibida su copia, uso, modificación o distribución
 * sin autorización expresa y por escrito del autor. Ver el archivo LICENSE.
 */
/*
 * Ip.java - Lo mínimo de IPv4 e ICMP para probar el túnel: armar un «echo request», reconocer uno y contestarlo, y el checksum de Internet. Nada más (el reenvío de paquetes reales es V1).
 */

public final class Ip {
  public static int checksum(byte[] b, int off, int len) {
    long s = 0;
    for (int i = 0; i + 1 < len; i += 2) s += ((b[off + i] & 255) << 8) | (b[off + i + 1] & 255);
    if ((len & 1) == 1) s += (b[off + len - 1] & 255) << 8;
    while ((s >> 16) != 0) s = (s & 0xffff) + (s >> 16);
    return (int) (~s & 0xffff);
  }

  static void put16(byte[] b, int off, int v) {
    b[off] = (byte) (v >> 8);
    b[off + 1] = (byte) v;
  }

  static void put32(byte[] b, int off, int v) {
    for (int i = 0; i < 4; i++) b[off + i] = (byte) (v >>> (24 - 8 * i));
  }

  /** Un paquete IPv4 con un ICMP echo (type 8 = petición, 0 = respuesta). */
  public static byte[] echo(int type, int src, int dst, int id, int seq, byte[] payload) {
    int total = 20 + 8 + payload.length;
    byte[] p = new byte[total];
    p[0] = 0x45;
    put16(p, 2, total);
    put16(p, 4, id);
    put16(p, 6, 0x4000);
    p[8] = 64;
    p[9] = 1;
    put32(p, 12, src);
    put32(p, 16, dst);
    put16(p, 10, checksum(p, 0, 20));
    p[20] = (byte) type;
    put16(p, 24, id);
    put16(p, 26, seq);
    for (int i = 0; i < payload.length; i++) p[28 + i] = payload[i];
    put16(p, 22, checksum(p, 20, total - 20));
    return p;
  }

  /** ¿Es (en los primeros len bytes) un paquete IPv4 con ICMP del tipo dado y checksums correctos? Devuelve su largo total, o -1. */
  public static int icmpType(byte[] p, int len, int type) {
    if (len < 28 || p[0] != 0x45 || p[9] != 1) return -1;
    int total = ((p[2] & 255) << 8) | (p[3] & 255);
    if (total < 28 || total > len) return -1;
    if (checksum(p, 0, 20) != 0 || checksum(p, 20, total - 20) != 0) return -1;
    return (p[20] & 255) == type && p[21] == 0 ? total : -1;
  }

  public static String str(int ip) {
    return ((ip >>> 24) & 255) + "." + ((ip >>> 16) & 255) + "." + ((ip >>> 8) & 255) + "." + (ip & 255);
  }

  public static int addr(String s) {
    int v = 0;
    int part = 0;
    int dots = 0;
    for (int i = 0; i <= s.length(); i++) {
      if (i == s.length() || s.charAt(i) == '.') {
        if (i == s.length() && dots != 3) return 0;
        v = (v << 8) | part;
        part = 0;
        dots++;
      } else {
        part = part * 10 + (s.charAt(i) - '0');
      }
    }
    return v;
  }

  /** La respuesta a una petición de eco: mismas direcciones intercambiadas y mismo contenido. */
  public static byte[] reply(byte[] req, int total) {
    byte[] r = new byte[total];
    for (int i = 0; i < total; i++) r[i] = req[i];
    for (int i = 0; i < 4; i++) {
      r[12 + i] = req[16 + i];
      r[16 + i] = req[12 + i];
    }
    r[8] = 64;
    put16(r, 10, 0);
    put16(r, 10, checksum(r, 0, 20));
    r[20] = 0;
    put16(r, 22, 0);
    put16(r, 22, checksum(r, 20, total - 20));
    return r;
  }
}
