/*
 * Copyright © 2018-2026 Diego Fernando Mayor Rojas. Todos los derechos reservados.
 *
 * Este archivo es parte de jelf. Software propietario:
 * queda prohibida su copia, uso, modificación o distribución
 * sin autorización expresa y por escrito del autor. Ver el archivo LICENSE.
 */
/*
 * Jvpn.java - VPN compatible con WireGuard de la nube de jelf (línea de órdenes), nativa y sin dependencias.
 * Fase V0 (el protocolo): genkey, pubkey, selftest y dos órdenes de PRUEBA con un par real (el WireGuard del kernel): «probe» (iniciador: apretón de manos y un ping por el túnel) y «listen» (respondedor:
 * contesta apretones de manos y pings). Todavía no hay interfaz TUN ni rutas (V1); los riesgos y cómo se validan, en RIESGOS.md.
 */

public class Jvpn {
  static final String NAME = "jvpn";
  static final String VERSION = "1.0.1";

  static void bad(String msg) {
    System.out.println(NAME + ": " + msg);
    System.exit(2);
  }

  static void usage() {
    System.out.println(NAME + " " + VERSION + ": VPN compatible con WireGuard de la nube de jelf (línea de órdenes), nativa y sin dependencias (fase V0: el protocolo).");
    System.out.println("órdenes: version, help, genkey, pubkey ARCHIVO, selftest, probe, listen");
    System.out.println("  genkey                      escribe una clave privada nueva (base64, como «wg genkey»)");
    System.out.println("  pubkey ARCHIVO              escribe la clave pública de la privada que hay en ARCHIVO");
    System.out.println("  probe ARCHIVO PUB_PAR IPv4:PUERTO ORIGEN DESTINO [N]   apretón de manos con el par y N pings (ICMP) por el túnel de ORIGEN a DESTINO");
    System.out.println("  listen ARCHIVO PUB_PAR PUERTO DIRECCION [N]             responde apretones de manos y contesta N pings dirigidos a DIRECCION (0 = sin fin)");
  }

  static byte[] readKey(String file) {
    File f = new File(file);
    if (!f.isFile() || f.length() > 4096) bad("no se puede leer la clave «" + file + "»");
    FileInputStream in = new FileInputStream(file);
    byte[] b = in.readAllBytes();
    in.close();
    byte[] k = B64.key(new String(b, 0, b.length));
    if (k == null) bad("«" + file + "» no tiene una clave de WireGuard (32 bytes en base64)");
    return k;
  }

  /** La clave precompartida opcional: el archivo que nombra JVPN_PSK_FILE (base64); null si no hay. */
  static byte[] psk() {
    String f = System.getenv("JVPN_PSK_FILE");
    return f == null || f.length() == 0 ? null : readKey(f);
  }

  static byte[] peerKey(String s) {
    byte[] k = B64.key(s);
    if (k == null) bad("la clave pública del par no es válida (32 bytes en base64)");
    return k;
  }

  public static void main(String[] args) {
    if (args.length == 0 || args[0].equals("help")) {
      usage();
      return;
    }
    String o = args[0];
    if (o.equals("version")) {
      System.out.println(NAME + " " + VERSION);
      return;
    }
    if (o.equals("genkey")) {
      System.out.println(B64.encode(Handshake.newPriv()));
      return;
    }
    if (o.equals("pubkey")) {
      if (args.length != 2) bad("uso: pubkey ARCHIVO");
      System.out.println(B64.encode(X25519.publicKey(readKey(args[1]))));
      return;
    }
    if (o.equals("selftest")) {
      System.exit(VpnTest.run() ? 0 : 1);
    }
    if (o.equals("probe")) {
      if (args.length < 6) bad("uso: probe ARCHIVO PUB_PAR IPv4:PUERTO ORIGEN DESTINO [N]");
      probe(readKey(args[1]), peerKey(args[2]), args[3], args[4], args[5], args.length > 6 ? Integer.parseInt(args[6]) : 1);
      return;
    }
    if (o.equals("listen")) {
      if (args.length < 5) bad("uso: listen ARCHIVO PUB_PAR PUERTO DIRECCION [N]");
      listen(readKey(args[1]), peerKey(args[2]), Integer.parseInt(args[3]), args[4], args.length > 5 ? Integer.parseInt(args[5]) : 0);
      return;
    }
    System.out.println(NAME + ": orden desconocida «" + o + "»; use «" + NAME + " help» para ver las órdenes");
    System.exit(2);
  }

  static void probe(byte[] priv, byte[] peer, String endpoint, String src, String dst, int count) {
    int colon = endpoint.indexOf(':');
    if (colon < 0) bad("el destino debe ser IPv4:PUERTO");
    long ip = Net.parseIp(endpoint.substring(0, colon));
    if (ip < 0) bad("«" + endpoint.substring(0, colon) + "» no es una dirección IPv4");
    int port = Integer.parseInt(endpoint.substring(colon + 1));
    int fd = Udp.bind(0, 0, true);
    if (fd < 0) bad("no se pudo abrir el socket UDP (error " + (-fd) + ")");
    Net.recvTimeout(fd, 3000);
    Handshake hs = new Handshake(priv, peer, psk());
    byte[] init = hs.createInitiation();
    if (init == null) bad("claves no válidas (punto de orden bajo)");
    Udp.sendTo(fd, (int) ip, port, init, 0, init.length);
    byte[] buf = new byte[2048];
    Session s = null;
    for (int tries = 0; tries < 3 && s == null; tries++) {
      int n = Udp.recvFrom(fd, buf, 0, buf.length);
      if (n < 0) {
        System.out.println(NAME + ": sin respuesta al apretón de manos (¿clave del par distinta o puerto cerrado?)");
        System.exit(1);
      }
      s = hs.consumeResponse(buf, n);
    }
    if (s == null) {
      System.out.println(NAME + ": la respuesta del par no es válida");
      System.exit(1);
    }
    System.out.println(NAME + ": apretón de manos completo con " + endpoint);
    int a = Ip.addr(src);
    int b = Ip.addr(dst);
    int good = 0;
    for (int i = 1; i <= count; i++) {
      byte[] req = Ip.echo(8, a, b, 0x4a56, i, "jvpn por el tunel".getBytes());
      byte[] m = s.seal(req, req.length);
      long t0 = System.currentTimeMillis();
      Udp.sendTo(fd, (int) ip, port, m, 0, m.length);
      for (;;) {
        int n = Udp.recvFrom(fd, buf, 0, buf.length);
        if (n < 0) {
          System.out.println(NAME + ": ping " + i + ": sin respuesta");
          break;
        }
        byte[] pt = s.open(buf, n);
        if (pt == null) continue;
        int tot = Ip.icmpType(pt, pt.length, 0);
        if (tot > 0 && (((pt[24] & 255) << 8) | (pt[25] & 255)) == 0x4a56 && (((pt[26] & 255) << 8) | (pt[27] & 255)) == i) {
          System.out.println(NAME + ": ping " + i + ": respuesta de " + dst + " en " + (System.currentTimeMillis() - t0) + " ms");
          good++;
          break;
        }
      }
    }
    Udp.close(fd);
    System.exit(good == count ? 0 : 1);
  }

  static void listen(byte[] priv, byte[] peer, int port, String addr, int max) {
    int fd = Udp.bind(0, port, true);
    if (fd < 0) bad("no se pudo escuchar en el puerto " + port + " (error " + (-fd) + ")");
    Handshake hs = new Handshake(priv, peer, psk());
    Session s = null;
    int me = Ip.addr(addr);
    int answered = 0;
    int peerIp = 0;
    int peerPort = 0;
    byte[] buf = new byte[2048];
    System.out.println(NAME + ": escuchando en UDP " + port);
    System.out.flush();
    for (;;) {
      int n = Udp.recvFrom(fd, buf, 0, buf.length);
      if (n < 0) continue;
      if (n >= 1 && buf[0] == 1) {
        boolean accepted = hs.consumeInitiation(buf, n);
        if (!accepted) System.out.println(NAME + ": iniciación rechazada (" + n + " bytes)");
        if (accepted) {
          byte[] r = hs.createResponse();
          if (r != null) {
            peerIp = Udp.srcIp;
            peerPort = Udp.srcPort;
            Udp.sendTo(fd, peerIp, peerPort, r, 0, r.length);
            s = hs.pending;
            System.out.println(NAME + ": apretón de manos aceptado");
            System.out.flush();
          }
        }
        continue;
      }
      if (s == null) continue;
      byte[] pt = s.open(buf, n);
      if (pt == null) continue;
      int tot = Ip.icmpType(pt, pt.length, 8);
      if (tot > 0) {
        int dst = ((pt[16] & 255) << 24) | ((pt[17] & 255) << 16) | ((pt[18] & 255) << 8) | (pt[19] & 255);
        if (dst != me) continue;
        byte[] rep = Ip.reply(pt, tot);
        byte[] m = s.seal(rep, rep.length);
        Udp.sendTo(fd, Udp.srcIp, Udp.srcPort, m, 0, m.length);
        answered++;
        System.out.println(NAME + ": ping contestado (" + answered + ")");
        System.out.flush();
        if (max > 0 && answered >= max) return;
      }
    }
  }
}
