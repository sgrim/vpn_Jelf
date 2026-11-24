/*
 * Copyright © 2018-2026 Diego Fernando Mayor Rojas. Todos los derechos reservados.
 *
 * Este archivo es parte de jelf. Software propietario:
 * queda prohibida su copia, uso, modificación o distribución
 * sin autorización expresa y por escrito del autor. Ver el archivo LICENSE.
 */
/*
 * Config.java - El archivo de configuración (subconjunto del formato de wg-quick, solo IPv4): [Interface] con PrivateKey y ListenPort; uno o más [Peer] con PublicKey, PresharedKey, AllowedIPs, Endpoint y
 * PersistentKeepalive. ESTRICTO: una clave desconocida, un valor mal formado, una dirección IPv6, un par repetido o dos pares con la misma ruta exacta son un error con su línea (una configuración que
 * se interpreta a medias en una VPN es una fuga). Las claves de wg-quick que se aplican FUERA del programa (Address, DNS, MTU, Table, PreUp, PostUp...) se aceptan, NO se aplican y se listan en warnings.
 * El archivo guarda claves privadas: quien lo lee debe exigir permisos 0600 (looseMode).
 */

public final class Config {
  public static final int MAX_PEERS = 256;
  public static final int MAX_ROUTES = 64;

  public static final class PeerConf {
    public byte[] pub;
    public byte[] psk;
    public int[] nets = new int[4];
    public int[] masks = new int[4];
    public int routes;
    public boolean hasEndpoint;
    public int endpointIp;
    /** Si el Endpoint era un NOMBRE: el nombre (se resuelve al arrancar, una sola vez; endpointIp vale 0 hasta entonces). */
    public String endpointHost;
    public int endpointPort;
    public int keepalive;
    public int line;
  }

  public byte[] privateKey;
  public int listenPort;
  /** SO_MARK de los paquetes UDP del túnel (0 = sin marca): una regla de rutas «not fwmark N» deja pasar por el túnel todo MENOS estos paquetes. */
  public int fwmark;
  public PeerConf[] peers = new PeerConf[4];
  public int peerCount;
  public StringBuilder warnings = new StringBuilder();
  public String error;

  boolean fail(int line, String msg) {
    error = "línea " + line + ": " + msg;
    return false;
  }

  static boolean ignoredKey(String k) {
    return k.equals("address") || k.equals("dns") || k.equals("mtu") || k.equals("table") || k.equals("preup") || k.equals("postup") || k.equals("predown") || k.equals("postdown") || k.equals("saveconfig");
  }

  /** Agrega una ruta CIDR IPv4 ("10.0.0.0/24") al par; false si no es válida. */
  boolean addRoute(PeerConf p, String s, int line) {
    int slash = s.indexOf('/');
    if (slash < 0) return fail(line, "AllowedIPs: «" + s + "» no es IPv4/BITS (IPv6 todavía no se admite)");
    long ip = Net.parseIp(s.substring(0, slash).trim());
    int bits = -1;
    String b = s.substring(slash + 1).trim();
    if (b.length() > 0 && b.length() <= 2) {
      bits = 0;
      for (int i = 0; i < b.length(); i++) {
        int d = b.charAt(i) - '0';
        if (d < 0 || d > 9) {
          bits = -1;
          break;
        }
        bits = bits * 10 + d;
      }
    }
    if (ip < 0 || bits < 0 || bits > 32) return fail(line, "AllowedIPs: «" + s + "» no es IPv4/BITS (IPv6 todavía no se admite)");
    int mask = bits == 0 ? 0 : (int) (0xffffffffL << (32 - bits));
    int net = (int) ip & mask;
    if ((int) ip != net) return fail(line, "AllowedIPs: «" + s + "» tiene bits de host (use " + Ip.str(net) + "/" + bits + ")");
    if (p.routes == MAX_ROUTES) return fail(line, "demasiadas rutas en un par (máximo " + MAX_ROUTES + ")");
    if (p.routes == p.nets.length) {
      int[] n2 = new int[p.routes * 2];
      int[] m2 = new int[p.routes * 2];
      for (int i = 0; i < p.routes; i++) {
        n2[i] = p.nets[i];
        m2[i] = p.masks[i];
      }
      p.nets = n2;
      p.masks = m2;
    }
    p.nets[p.routes] = net;
    p.masks[p.routes] = mask;
    p.routes++;
    return true;
  }

  public static Config parse(String text) {
    Config c = new Config();
    c.run(text);
    return c;
  }

  void run(String text) {
    int section = 0; // 0 = antes de todo, 1 = Interface, 2 = Peer
    PeerConf cur = null;
    boolean haveInterface = false;
    int line = 0;
    int pos = 0;
    while (pos <= text.length()) {
      int e = text.indexOf('\n', pos);
      if (e < 0) e = text.length();
      String l = text.substring(pos, e);
      pos = e + 1;
      line++;
      int hash = l.indexOf('#');
      if (hash >= 0) l = l.substring(0, hash);
      l = l.trim();
      if (l.length() == 0) {
        if (e >= text.length()) break;
        continue;
      }
      if (l.charAt(0) == '[') {
        String s = l.toLowerCase();
        if (s.equals("[interface]")) {
          if (haveInterface) {
            fail(line, "dos secciones [Interface]");
            return;
          }
          haveInterface = true;
          section = 1;
        } else if (s.equals("[peer]")) {
          if (peerCount == MAX_PEERS) {
            fail(line, "demasiados pares (máximo " + MAX_PEERS + ")");
            return;
          }
          cur = new PeerConf();
          cur.line = line;
          if (peerCount == peers.length) {
            PeerConf[] g = new PeerConf[peerCount * 2];
            for (int i = 0; i < peerCount; i++) g[i] = peers[i];
            peers = g;
          }
          peers[peerCount++] = cur;
          section = 2;
        } else {
          fail(line, "sección desconocida «" + l + "»");
          return;
        }
        continue;
      }
      int eq = l.indexOf('=');
      if (eq < 0 || section == 0) {
        fail(line, section == 0 ? "una clave antes de [Interface] o [Peer]" : "se esperaba «clave = valor»");
        return;
      }
      String k = l.substring(0, eq).trim().toLowerCase();
      String v = l.substring(eq + 1).trim();
      if (section == 1) {
        if (k.equals("privatekey")) {
          if (privateKey != null) {
            fail(line, "PrivateKey repetida");
            return;
          }
          privateKey = B64.key(v);
          if (privateKey == null) {
            fail(line, "PrivateKey no es una clave de 32 bytes en base64");
            return;
          }
        } else if (k.equals("listenport")) {
          int p = parseInt(v, 65535);
          if (p < 0) {
            fail(line, "ListenPort debe ser un número de 0 a 65535");
            return;
          }
          listenPort = p;
        } else if (k.equals("fwmark")) {
          int mk = v.equals("off") ? 0 : (v.startsWith("0x") ? parseHex(v.substring(2)) : parseInt(v, 2147483647));
          if (mk < 0) {
            fail(line, "FwMark debe ser un número (decimal o 0x...) o off");
            return;
          }
          fwmark = mk;
        } else if (ignoredKey(k)) {
          warnings.append("jvpn: AVISO: línea " + line + ": «" + l.substring(0, eq).trim() + "» no se aplica (configure la dirección, las rutas y el DNS con «ip»)\n");
        } else {
          fail(line, "clave desconocida «" + l.substring(0, eq).trim() + "» en [Interface]");
          return;
        }
      } else {
        if (k.equals("publickey")) {
          if (cur.pub != null) {
            fail(line, "PublicKey repetida");
            return;
          }
          cur.pub = B64.key(v);
          if (cur.pub == null) {
            fail(line, "PublicKey no es una clave de 32 bytes en base64");
            return;
          }
        } else if (k.equals("presharedkey")) {
          cur.psk = B64.key(v);
          if (cur.psk == null) {
            fail(line, "PresharedKey no es una clave de 32 bytes en base64");
            return;
          }
        } else if (k.equals("allowedips")) {
          int from = 0;
          while (from <= v.length()) {
            int comma = v.indexOf(',', from);
            if (comma < 0) comma = v.length();
            String item = v.substring(from, comma).trim();
            from = comma + 1;
            if (item.length() == 0) {
              if (comma >= v.length() && from > v.length()) break;
              fail(line, "AllowedIPs con un elemento vacío");
              return;
            }
            if (!addRoute(cur, item, line)) return;
          }
        } else if (k.equals("endpoint")) {
          int colon = v.lastIndexOf(':');
          String hostPart = colon < 0 ? "" : v.substring(0, colon);
          long ip = colon < 0 ? -1 : Net.parseIp(hostPart);
          int port = colon < 0 ? -1 : parseInt(v.substring(colon + 1), 65535);
          if (port <= 0 || (ip < 0 && !Dns.validName(hostPart))) {
            fail(line, "Endpoint debe ser IPv4:PUERTO o NOMBRE:PUERTO (IPv6 todavía no)");
            return;
          }
          cur.hasEndpoint = true;
          if (ip >= 0) cur.endpointIp = (int) ip;
          else cur.endpointHost = hostPart;
          cur.endpointPort = port;
        } else if (k.equals("persistentkeepalive")) {
          int p = parseInt(v, 65535);
          if (p < 0) {
            fail(line, "PersistentKeepalive debe ser un número de segundos");
            return;
          }
          cur.keepalive = p;
        } else {
          fail(line, "clave desconocida «" + l.substring(0, eq).trim() + "» en [Peer]");
          return;
        }
      }
      if (e >= text.length()) break;
    }
    if (privateKey == null) {
      error = "falta PrivateKey en [Interface]";
      return;
    }
    if (peerCount == 0) {
      error = "no hay ningún [Peer]";
      return;
    }
    for (int i = 0; i < peerCount; i++) {
      if (peers[i].pub == null) {
        error = "línea " + peers[i].line + ": el [Peer] no tiene PublicKey";
        return;
      }
      if (peers[i].routes == 0) {
        error = "línea " + peers[i].line + ": el [Peer] no tiene AllowedIPs (no recibiría ni enviaría nada)";
        return;
      }
      for (int j = 0; j < i; j++) {
        if (Wg.same(peers[i].pub, 0, peers[j].pub, 0, 32)) {
          error = "línea " + peers[i].line + ": el par está repetido (también en la línea " + peers[j].line + ")";
          return;
        }
        for (int a = 0; a < peers[i].routes; a++) {
          for (int b = 0; b < peers[j].routes; b++) {
            if (peers[i].nets[a] == peers[j].nets[b] && peers[i].masks[a] == peers[j].masks[b]) {
              error = "línea " + peers[i].line + ": la ruta " + Ip.str(peers[i].nets[a]) + " ya es de otro par (línea " + peers[j].line + "): sería ambiguo";
              return;
            }
          }
        }
      }
    }
  }

  static int parseHex(String s) {
    if (s.length() == 0 || s.length() > 8) return -1;
    long v = 0;
    for (int i = 0; i < s.length(); i++) {
      char ch = s.charAt(i);
      int d = ch >= '0' && ch <= '9' ? ch - '0' : (ch >= 'a' && ch <= 'f' ? ch - 'a' + 10 : (ch >= 'A' && ch <= 'F' ? ch - 'A' + 10 : -1));
      if (d < 0) return -1;
      v = v * 16 + d;
    }
    return v > 2147483647L ? -1 : (int) v;
  }

  static int parseInt(String s, int max) {
    if (s.length() == 0 || s.length() > 6) return -1;
    int v = 0;
    for (int i = 0; i < s.length(); i++) {
      int d = s.charAt(i) - '0';
      if (d < 0 || d > 9) return -1;
      v = v * 10 + d;
    }
    return v > max ? -1 : v;
  }

  /** ¿Tiene el archivo permisos que otros pueden usar (grupo u otros)? Solo se sabe en x86-64 (formato de stat); en otros procesadores devuelve false. */
  public static boolean looseMode(String path) {
    if (Os.FSTAT != 5) return false;
    byte[] p = (path + "\0").getBytes();
    long fd = Os.open(Sys.addr(p) + 8, 0, 0);
    if (fd < 0) return false;
    long[] st = new long[18];
    long r = Sys.syscall(Os.FSTAT, fd, Sys.addr(st) + 8);
    Sys.syscall(Os.CLOSE, fd);
    if (r != 0) return false;
    return ((st[3] & 0xFFFFFFFFL) & 077) != 0;
  }
}
