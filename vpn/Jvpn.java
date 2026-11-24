/*
 * Copyright © 2018-2026 Diego Fernando Mayor Rojas. Todos los derechos reservados.
 *
 * Este archivo es parte de jelf. Software propietario:
 * queda prohibida su copia, uso, modificación o distribución
 * sin autorización expresa y por escrito del autor. Ver el archivo LICENSE.
 */
/*
 * Jvpn.java - VPN compatible con WireGuard de la nube de jelf (línea de órdenes), nativa y sin dependencias.
 * Esqueleto inicial: la orden «version» y la ayuda, con el rechazo claro de lo desconocido (la causa y qué hacer). Lo demás se añade siguiendo PENDIENTE.md; los riesgos y cómo se validan, en RIESGOS.md.
 */

public class Jvpn {
  static final String NAME = "jvpn";
  static final String VERSION = "1.0.1";

  public static void main(String[] args) {
    if (args.length == 0 || args[0].equals("help")) {
      System.out.println(NAME + " " + VERSION + ": VPN compatible con WireGuard de la nube de jelf (línea de órdenes), nativa y sin dependencias.");
      System.out.println("órdenes: version, help");
      return;
    }
    if (args[0].equals("version")) {
      System.out.println(NAME + " " + VERSION);
      return;
    }
    System.out.println(NAME + ": orden desconocida «" + args[0] + "»; use «" + NAME + " help» para ver las órdenes");
    System.exit(2);
  }
}
