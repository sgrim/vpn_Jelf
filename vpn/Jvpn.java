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
    System.out.println("órdenes: version, help, genkey, pubkey ARCHIVO, selftest, up, probe, listen, cookie-probe");
    System.out.println("  genkey                      escribe una clave privada nueva (base64, como «wg genkey»)");
    System.out.println("  pubkey ARCHIVO              escribe la clave pública de la privada que hay en ARCHIVO");
    System.out.println("  up CONFIG --tun NOMBRE [--user UID] [--force-cookies] [-v]");
    System.out.println("      túnel con varios pares entre la interfaz TUN y UDP; CONFIG es un subconjunto del formato de wg-quick (IPv4) con permisos 0600; hace falta CAP_NET_ADMIN para crear la TUN y --user suelta los privilegios después");
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
    if (o.equals("up")) {
      up(args);
      return;
    }
    if (o.equals("cookie-probe")) {
      if (args.length < 4) bad("uso: cookie-probe ARCHIVO PUB_PAR IPv4:PUERTO [N]");
      cookieProbe(readKey(args[1]), peerKey(args[2]), args[3], args.length > 4 ? Integer.parseInt(args[4]) : 30000);
      return;
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

  static void up(String[] a) {
    if (a.length < 2) bad("uso: up CONFIG --tun NOMBRE [--user UID] [--max-packets N] [--force-cookies] [-v]");
    String tunName = null;
    int uid = -1;
    long max = 0;
    Tunnel t = new Tunnel();
    for (int i = 2; i < a.length; i++) {
      if (a[i].equals("-v")) t.verbose = true;
      else if (a[i].equals("--force-cookies")) t.forceCookies = true;
      else if (i + 1 >= a.length) bad("falta el valor de " + a[i]);
      else if (a[i].equals("--tun")) tunName = a[++i];
      else if (a[i].equals("--user")) uid = Integer.parseInt(a[++i]);
      else if (a[i].equals("--max-packets")) max = Long.parseLong(a[++i]);
      else bad("opción desconocida «" + a[i] + "»");
    }
    if (tunName == null) bad("falta --tun NOMBRE");
    File f = new File(a[1]);
    if (!f.isFile() || f.length() > (1 << 20)) bad("no se puede leer la configuración «" + a[1] + "»");
    if (Config.looseMode(a[1])) bad("la configuración «" + a[1] + "» guarda claves privadas y la pueden leer otros usuarios: use «chmod 600 " + a[1] + "»");
    FileInputStream in = new FileInputStream(a[1]);
    byte[] raw = in.readAllBytes();
    in.close();
    Config c = Config.parse(new String(raw, 0, raw.length));
    for (int i = 0; i < raw.length; i++) raw[i] = 0;
    if (c.error != null) bad("configuración inválida: " + c.error);
    if (c.warnings.length() > 0) System.err.print(c.warnings.toString());
    t.setup(c);
    t.udp = Udp.bind(0, c.listenPort, false);
    if (t.udp < 0) bad("no se pudo abrir el socket UDP (error " + (-t.udp) + ")");
    t.tun = Tun.open(tunName);
    if (t.tun < 0) bad("no se pudo crear la interfaz TUN «" + tunName + "» (error " + (-t.tun) + "; hace falta CAP_NET_ADMIN y /dev/net/tun)");
    Tun.setBlocking(t.tun, false);
    System.out.println(NAME + ": interfaz " + Tun.name + " creada, UDP " + Udp.localPort(t.udp) + ", " + c.peerCount + " par(es)");
    if (uid > 0) {
      if (!Tun.dropPrivileges(uid, uid)) bad("no se pudieron soltar los privilegios (uid " + uid + ")");
      System.out.println(NAME + ": privilegios soltados (uid " + uid + ")");
    } else {
      System.out.println(NAME + ": AVISO: corre con los privilegios con que se lanzó; use --user UID");
    }
    System.out.flush();
    t.run(max);
    long rx = 0;
    long tx = 0;
    long dr = 0;
    for (int i = 0; i < t.peerCount; i++) {
      rx += t.peers[i].rxPackets;
      tx += t.peers[i].txPackets;
      dr += t.peers[i].dropped;
    }
    System.out.println(NAME + ": " + rx + " paquetes entregados a la TUN, " + tx + " enviados, " + dr + " descartados");
  }

  /**
   * Prueba contra un respondedor REAL bajo carga (el kernel): inunda con N iniciaciones falsas pero con MAC1 válido (le cuestan una curva elíptica cada una), y justo después manda una iniciación verdadera SIN
   * cookie. Un respondedor bajo carga debe contestar con una respuesta de cookie (no con la de apretón de manos); entonces se repite con MAC2 y debe contestar el apretón de manos. Sale 0 si todo ocurrió así.
   */
  static void cookieProbe(byte[] priv, byte[] peer, String endpoint, int count) {
    int colon = endpoint.indexOf(':');
    long ip = colon < 0 ? -1 : Net.parseIp(endpoint.substring(0, colon));
    if (ip < 0) bad("el destino debe ser IPv4:PUERTO");
    int port = Integer.parseInt(endpoint.substring(colon + 1));
    int fd = Udp.bind(0, 0, true);
    Net.recvTimeout(fd, 1500);
    byte[] key1 = Wg.mac1Key(peer);
    byte[][] pk = new byte[count][];
    for (int i = 0; i < count; i++) {
      byte[] m = Rand.bytes(Wg.INITIATION);
      m[0] = 1;
      m[1] = 0;
      m[2] = 0;
      m[3] = 0;
      Wg.copy(Wg.mac(key1, m, 116), 0, m, 116, 16);
      for (int j = 132; j < 148; j++) m[j] = 0;
      pk[i] = m;
    }
    byte[] drain = new byte[2048];
    int fakeReplies = 0;
    Net.setBlocking(fd, false); // durante la inundación se vacía el socket a menudo: las respuestas de cookie a las falsas llenarían el búfer y taparían la de la verdadera
    for (int i = 0; i < count; i++) {
      Udp.sendTo(fd, (int) ip, port, pk[i], 0, Wg.INITIATION);
      if ((i & 255) == 255) while (Udp.recvFrom(fd, drain, 0, drain.length) > 0) fakeReplies++;
    }
    Net.setBlocking(fd, true);
    Net.recvTimeout(fd, 1500);
    System.out.println(NAME + ": " + count + " iniciaciones falsas con MAC1 válido enviadas; el par ya contestó " + fakeReplies + " con cookies");
    Handshake hs = new Handshake(priv, peer, psk());
    byte[] init = hs.createInitiation();
    Udp.sendTo(fd, (int) ip, port, init, 0, init.length);
    byte[] buf = new byte[2048];
    boolean cookie = false;
    boolean answered = false;
    int replies = 0;
    long end = System.currentTimeMillis() + 4000;
    while (System.currentTimeMillis() < end && !answered) {
      int n = Udp.recvFrom(fd, buf, 0, buf.length);
      if (n < 0) break;
      if (n == Cookies.REPLY && buf[0] == 3) {
        replies++;
        if (!cookie && hs.consumeCookieReply(buf, n)) {
          cookie = true;
          System.out.println(NAME + ": cookie recibida y abierta (XChaCha20-Poly1305) entre " + replies + " respuestas de cookie");
          init = hs.createInitiation();
          Udp.sendTo(fd, (int) ip, port, init, 0, init.length);
        }
      } else if (n == Wg.RESPONSE && buf[0] == 2) {
        if (!cookie) {
          System.out.println(NAME + ": el par contestó el apretón de manos SIN pedir cookie: no estaba bajo carga (la prueba no vale)");
          System.exit(3);
        }
        Session s = hs.consumeResponse(buf, n);
        if (s != null) {
          answered = true;
          System.out.println(NAME + ": con el MAC2 de la cookie el par aceptó la iniciación: apretón de manos completo");
        }
      }
    }
    Udp.close(fd);
    if (!cookie) System.out.println(NAME + ": no llegó ninguna respuesta de cookie válida (" + replies + " respuestas de cookie en total)");
    System.exit(cookie && answered ? 0 : 1);
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
      if (n >= 1 && buf[0] == 3 && hs.consumeCookieReply(buf, n)) { // el par está bajo carga: se repite la iniciación con MAC2
        System.out.println(NAME + ": el par pidió una cookie (bajo carga); se repite la iniciación con MAC2");
        init = hs.createInitiation();
        Udp.sendTo(fd, (int) ip, port, init, 0, init.length);
        continue;
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
