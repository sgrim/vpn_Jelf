/*
 * Copyright © 2018-2026 Diego Fernando Mayor Rojas. Todos los derechos reservados.
 *
 * Este archivo es parte de jelf. Software propietario:
 * queda prohibida su copia, uso, modificación o distribución
 * sin autorización expresa y por escrito del autor. Ver el archivo LICENSE.
 */
/*
 * DnsStub.java - Un servidor DNS de PRUEBA (solo para tools/killswitch_oracle.sh): contesta cada consulta de tipo A con 192.0.2.7 y escribe «q IP» con el origen de cada consulta, para ver DESDE DÓNDE llegan
 * las consultas de DNS (por el túnel o en claro). No es un servidor real: sin recursión, sin caché, sin validación (el mensaje que no parece una consulta se ignora).
 */

public class DnsStub {
  public static void main(String[] args) {
    int bindIp = 0;
    if (args.length > 1) bindIp = (int) Net.parseIp(args[1]); // con una dirección: las respuestas salen con ELLA de origen (un cliente descarta una respuesta que viene de otra dirección)
    int fd = Udp.bind(bindIp, args.length > 0 ? Integer.parseInt(args[0]) : 53, true);
    if (fd < 0) {
      System.out.println("no se pudo escuchar (error " + (-fd) + ")");
      System.exit(1);
    }
    byte[] q = new byte[512];
    byte[] r = new byte[600];
    System.out.println("escuchando");
    System.out.flush();
    for (;;) {
      int n = Udp.recvFrom(fd, q, 0, q.length);
      if (n < 17 || (q[2] & 0x80) != 0) continue; // demasiado corto o ya es una respuesta
      int ip = Udp.srcIp;
      int port = Udp.srcPort;
      int p = 12;
      while (p < n && q[p] != 0) p += (q[p] & 255) + 1; // el nombre de la pregunta
      if (p + 5 > n) continue;
      int end = p + 5; // fin de la pregunta: nombre (con el cero), tipo y clase
      for (int i = 0; i < end; i++) r[i] = q[i];
      r[2] = (byte) 0x81;
      r[3] = (byte) 0x80;
      r[6] = 0;
      r[7] = 1; // una respuesta
      r[8] = 0;
      r[9] = 0;
      r[10] = 0;
      r[11] = 0;
      int o = end;
      r[o++] = (byte) 0xc0;
      r[o++] = 0x0c;
      r[o++] = 0;
      r[o++] = 1; // tipo A
      r[o++] = 0;
      r[o++] = 1; // clase IN
      r[o++] = 0;
      r[o++] = 0;
      r[o++] = 0;
      r[o++] = 1; // TTL 1 s
      r[o++] = 0;
      r[o++] = 4;
      r[o++] = (byte) 192;
      r[o++] = 0;
      r[o++] = 2;
      r[o++] = 7;
      Udp.sendTo(fd, ip, port, r, 0, o);
      System.out.println("q " + ((ip >>> 24) & 255) + "." + ((ip >>> 16) & 255) + "." + ((ip >>> 8) & 255) + "." + (ip & 255));
      System.out.flush();
    }
  }
}
