/*
 * Copyright © 2018-2026 Diego Fernando Mayor Rojas. Todos los derechos reservados.
 *
 * Este archivo es parte de jelf. Software propietario:
 * queda prohibida su copia, uso, modificación o distribución
 * sin autorización expresa y por escrito del autor. Ver el archivo LICENSE.
 */
/*
 * Tunnel.java - «jvpn up CONFIG»: un túnel WireGuard con VARIOS pares entre una interfaz TUN y un socket UDP, en modo usuario.
 *   TUN → UDP: cada paquete IPv4 se envía al par cuya ruta (AllowedIPs) COINCIDE MÁS LARGO con el destino (enrutamiento por clave criptográfica); sin ninguna ruta, se descarta. Sin sesión vigente se guarda el último paquete
 *   y se inicia el apretón de manos con ese par.
 *   UDP → TUN: el mensaje de datos se atribuye al par por su índice receptor, se abre con su sesión actual o la anterior y el paquete interior debe ser IPv4, con largo coherente y ORIGEN dentro de las rutas de ESE par
 *   (sin esto un par autenticado podría suplantar a otro o a cualquier origen). Una iniciación elige al par por la clave estática que descifra, que debe ser la de un par configurado.
 * Todo lo que llega por UDP es hostil. Se crea la TUN y se enlaza el socket CON privilegios y después se sueltan (--user), antes de leer el primer paquete. Tiempos como WireGuard (renovar a los 120 s al enviar, no usar
 * sesiones de más de 180 s, reintentos cada 5 s, hasta 3). Iniciaciones: solo se cuentan las de MAC1 válido, tope de 20 por segundo para todo el dispositivo y cookies cuando pasan de 5. IPv4 solamente.
 */

public final class Tunnel {
  static final long REKEY_AFTER_MS = 120000;
  static final long REJECT_AFTER_MS = 180000;
  static final long REKEY_TIMEOUT_MS = 5000;
  static final int MAX_ATTEMPTS = 3;
  static final int MAX_INITIATIONS_PER_SEC = 20;

  /** El estado de un par. */
  static final class Peer {
    Config.PeerConf conf;
    Handshake hs;
    boolean haveEndpoint;
    int ip;
    int port;
    Session cur;
    long curSince;
    Session prev;
    boolean handshaking;
    long handshakeSent;
    int attempts;
    byte[] queued;
    int queuedLen;
    long lastSend;
    long rxPackets;
    long txPackets;
    long dropped;
  }

  Peer[] peers;
  final byte[] txBuf = new byte[65664]; // búferes fijos del camino caliente: no se reserva nada por paquete
  static final int POOL = 9216; // un datagrama por búfer del lote (MTU de hasta jumbo)
  final byte[][] txPool = new byte[Udp.BATCH][POOL];
  final byte[][] rxPool = new byte[Udp.BATCH][POOL];
  final byte[] rxPlain = new byte[65664];
  int peerCount;
  byte[] sPub;
  Cookies cookies = new Cookies();
  int udp;
  int tun;
  boolean verbose;
  boolean forceCookies;
  long secStart;
  int secCount;

  void log(String s) {
    if (verbose) System.err.println("jvpn: " + s);
  }

  void setup(Config c) {
    peerCount = c.peerCount;
    peers = new Peer[peerCount];
    for (int i = 0; i < peerCount; i++) {
      Peer p = new Peer();
      p.conf = c.peers[i];
      p.hs = new Handshake(c.privateKey, p.conf.pub, p.conf.psk);
      p.hs.cookies = cookies;
      p.haveEndpoint = p.conf.hasEndpoint;
      p.ip = p.conf.endpointIp;
      p.port = p.conf.endpointPort;
      peers[i] = p;
    }
    sPub = peers[0].hs.sPub;
  }

  static int ipAt(byte[] p, int off) {
    return ((p[off] & 255) << 24) | ((p[off + 1] & 255) << 16) | ((p[off + 2] & 255) << 8) | (p[off + 3] & 255);
  }

  /** El largo total de un paquete IPv4 bien formado en p[0..len), o -1. */
  static int ipv4Length(byte[] p, int len) {
    if (len < 20 || (p[0] & 0xf0) != 0x40 || (p[0] & 15) < 5) return -1;
    int total = ((p[2] & 255) << 8) | (p[3] & 255);
    if (total < (p[0] & 15) * 4 || total > len) return -1;
    return total;
  }

  /** ¿La dirección está en alguna ruta del par? */
  static boolean allowed(Peer p, int ip) {
    for (int i = 0; i < p.conf.routes; i++) if ((ip & p.conf.masks[i]) == p.conf.nets[i]) return true;
    return false;
  }

  /** El par con la ruta más específica (máscara más larga) que contiene la dirección, o null. */
  Peer route(int ip) {
    Peer best = null;
    long bestMask = -1;
    for (int i = 0; i < peerCount; i++) {
      Config.PeerConf c = peers[i].conf;
      for (int r = 0; r < c.routes; r++) {
        if ((ip & c.masks[r]) == c.nets[r]) {
          long m = c.masks[r] & 0xffffffffL;
          if (best == null || m > bestMask) {
            best = peers[i];
            bestMask = m;
          }
        }
      }
    }
    return best;
  }

  /** Envía con una sola llamada los datagramas de datos acumulados. */
  void flushSend() {
    if (Udp.queuedCount() > 0) Udp.sendFlush(udp);
  }

  void send(Peer p, byte[] m, int len) {
    if (p.haveEndpoint) Udp.sendTo(udp, p.ip, p.port, m, 0, len);
  }

  void startHandshake(Peer p, long now) {
    if (!p.haveEndpoint) return;
    byte[] m = p.hs.createInitiation();
    if (m == null) return;
    p.handshaking = true;
    p.handshakeSent = now;
    p.attempts++;
    send(p, m, m.length);
    log("iniciación enviada (intento " + p.attempts + ")");
  }

  boolean sendPacket(Peer p, byte[] pkt, int len, long now) {
    if (p.cur == null || now - p.curSince >= REJECT_AFTER_MS) {
      p.cur = null;
      return false;
    }
    if (p.cur.initiator && now - p.curSince >= REKEY_AFTER_MS && !p.handshaking) {
      p.attempts = 0;
      startHandshake(p, now);
    }
    if (Udp.queuedCount() == Udp.BATCH) flushSend();
    byte[] slot = txPool[Udp.queuedCount()];
    int ml = p.cur.sealInto(pkt, len, slot);
    if (ml < 0) {
      p.cur = null;
      return false;
    }
    if (p.haveEndpoint) Udp.sendAdd(slot, 0, ml, p.ip, p.port); // se envía por lotes (sendmmsg) al terminar de atender lo que haya en la TUN
    p.lastSend = now;
    return true;
  }

  void onTun(byte[] buf, int n, long now) {
    int total = ipv4Length(buf, n);
    if (total < 0) return;
    Peer p = route(ipAt(buf, 16));
    if (p == null) return; // ningún par tiene esa ruta
    if (sendPacket(p, buf, total, now)) {
      p.txPackets++;
      return;
    }
    p.queued = new byte[total];
    for (int i = 0; i < total; i++) p.queued[i] = buf[i];
    p.queuedLen = total;
    if (!p.handshaking) {
      p.attempts = 0;
      startHandshake(p, now);
    }
  }

  void flushQueue(Peer p, long now) {
    if (p.queued != null && p.cur != null) {
      if (sendPacket(p, p.queued, p.queuedLen, now)) p.txPackets++;
      p.queued = null;
    }
  }

  Peer byLocalIndex(int idx) {
    for (int i = 0; i < peerCount; i++) {
      Peer p = peers[i];
      if (p.hs.waiting && p.hs.localIndex == idx) return p;
    }
    return null;
  }

  Peer bySessionIndex(int idx) {
    for (int i = 0; i < peerCount; i++) {
      Peer p = peers[i];
      if ((p.cur != null && p.cur.localIndex == idx) || (p.prev != null && p.prev.localIndex == idx)) return p;
    }
    return null;
  }

  void onInitiation(byte[] buf, int n, long now, int srcIp, int srcPort) {
    Handshake any = peers[0].hs;
    if (!any.mac1Ok(buf, n)) return; // lo barato primero: sin MAC1 válido no se cuenta ni se gasta nada
    if (now - secStart >= 1000) {
      secStart = now;
      secCount = 0;
    }
    if (++secCount > MAX_INITIATIONS_PER_SEC) return; // tope duro del dispositivo: cada iniciación cuesta curvas elípticas
    boolean load = forceCookies || secCount > MAX_INITIATIONS_PER_SEC / 4;
    if (load && !cookies.mac2Valid(buf, 132, srcIp, srcPort, now)) {
      byte[] r = cookies.reply(buf, 116, srcIp, srcPort, sPub, now);
      Udp.sendTo(udp, srcIp, srcPort, r, 0, Cookies.REPLY);
      log("bajo carga: respuesta de cookie enviada");
      return;
    }
    Handshake.Init in = any.openInitiation(buf, n);
    if (in == null) return;
    Peer p = null;
    for (int i = 0; i < peerCount && p == null; i++) if (Wg.same(in.stat, 0, peers[i].conf.pub, 0, 32)) p = peers[i];
    if (p == null) {
      log("iniciación de una clave que no es de ningún par: descartada");
      return;
    }
    if (!p.hs.consumeInitiation(in, buf)) return;
    byte[] r = p.hs.createResponse();
    if (r == null) return;
    p.ip = srcIp;
    p.port = srcPort;
    p.haveEndpoint = true;
    send(p, r, r.length);
    p.prev = p.cur;
    p.cur = p.hs.pending;
    p.curSince = now;
    p.handshaking = false;
    log("apretón de manos aceptado (respondedor)");
  }

  void onUdp(byte[] buf, int n, long now, int srcIp, int srcPort) {
    if (n < 4) return;
    int type = buf[0];
    if (type == 1) {
      onInitiation(buf, n, now, srcIp, srcPort);
    } else if (type == 3) {
      Peer p = n >= 8 ? byLocalIndex(Wg.getLE32(buf, 4)) : null;
      if (p != null && p.handshaking && p.hs.consumeCookieReply(buf, n) && p.attempts < MAX_ATTEMPTS) {
        log("cookie recibida: se repite la iniciación con MAC2");
        startHandshake(p, now);
      }
    } else if (type == 2) {
      Peer p = n >= 12 ? byLocalIndex(Wg.getLE32(buf, 8)) : null;
      if (p == null) return;
      Session s = p.hs.consumeResponse(buf, n);
      if (s == null) return;
      p.prev = p.cur;
      p.cur = s;
      p.curSince = now;
      p.handshaking = false;
      p.attempts = 0;
      log("apretón de manos completo (iniciador)");
      int kl = p.cur.sealInto(txBuf, 0, txBuf); // el primer mensaje de datos lo manda el iniciador y confirma la sesión
      send(p, txBuf, kl);
      p.lastSend = now;
      flushQueue(p, now);
    } else if (type == 4) {
      Peer p = n >= 8 ? bySessionIndex(Wg.getLE32(buf, 4)) : null;
      if (p == null) {
        log("datos para un índice de sesión desconocido (" + n + " bytes)");
        return;
      }
      int pl = -1;
      if (p.cur != null && p.cur.localIndex == Wg.getLE32(buf, 4) && now - p.curSince < REJECT_AFTER_MS + 30000) pl = p.cur.openInto(buf, n, rxPlain);
      else if (p.prev != null && p.prev.localIndex == Wg.getLE32(buf, 4)) pl = p.prev.openInto(buf, n, rxPlain);
      if (pl < 0) {
        log("mensaje de datos que no abre (" + n + " bytes)");
        p.dropped++;
        return;
      }
      p.ip = srcIp; // itinerancia: solo tras autenticar un mensaje
      p.port = srcPort;
      p.haveEndpoint = true;
      if (pl == 0) return; // keepalive
      int total = ipv4Length(rxPlain, pl);
      if (total < 0 || !allowed(p, ipAt(rxPlain, 12))) {
        log("descartado: paquete de " + pl + " bytes" + (total < 0 ? " mal formado" : " con origen " + Ip.str(ipAt(rxPlain, 12)) + " fuera de las rutas del par"));
        p.dropped++; // origen fuera de las rutas de ESTE par: suplantación
        return;
      }
      Tun.write(tun, rxPlain, 0, total);
      p.rxPackets++;
    }
  }

  void timers(long now) {
    for (int i = 0; i < peerCount; i++) {
      Peer p = peers[i];
      if (p.cur != null && now - p.curSince >= REJECT_AFTER_MS) p.cur = null;
      if (p.prev != null && now - p.curSince >= REJECT_AFTER_MS) p.prev = null;
      if (p.handshaking && now - p.handshakeSent >= REKEY_TIMEOUT_MS) {
        if (p.attempts >= MAX_ATTEMPTS) {
          p.handshaking = false;
          p.queued = null;
          log("sin respuesta del par: se abandona el apretón de manos");
        } else {
          startHandshake(p, now);
        }
      }
      int ka = p.conf.keepalive;
      if (ka > 0 && p.haveEndpoint && now - p.lastSend >= ka * 1000L) {
        if (p.cur != null) {
          int kl = p.cur.sealInto(txBuf, 0, txBuf);
          if (kl >= 0) {
            send(p, txBuf, kl);
            p.lastSend = now;
          }
        } else if (!p.handshaking) {
          p.attempts = 0;
          startHandshake(p, now);
          p.lastSend = now;
        }
      }
    }
  }

  long delivered() {
    long t = 0;
    for (int i = 0; i < peerCount; i++) t += peers[i].rxPackets;
    return t;
  }

  /** Corre el túnel hasta que se mate el proceso. maxPackets > 0 lo termina tras ese número de paquetes entregados a la TUN (para las pruebas). */
  void run(long maxPackets) {
    Poller poll = new Poller(4);
    poll.add(udp, Net.IN);
    poll.add(tun, Net.IN);
    byte[] tbuf = new byte[65536];
    long now = System.currentTimeMillis();
    for (int i = 0; i < peerCount; i++) if (peers[i].haveEndpoint) startHandshake(peers[i], now);
    for (;;) {
      int n = poll.await(1000);
      now = System.currentTimeMillis();
      for (int i = 0; i < n; i++) {
        int fd = poll.fd(i);
        if (fd == udp) {
          for (int k = 0; k < 2; k++) { // se vacía el socket por lotes de hasta 32 datagramas con una llamada, con tope para no dejar sin atender la TUN
            int r = Udp.recvBatch(udp, rxPool, Udp.BATCH);
            if (r <= 0) break;
            for (int j = 0; j < r; j++) onUdp(rxPool[j], Udp.batchLen[j], now, Udp.batchIp[j], Udp.batchPort[j]);
            if (r < Udp.BATCH) break;
          }
          flushSend();
        } else if (fd == tun) {
          for (int k = 0; k < 64; k++) {
            int r = Tun.read(tun, tbuf, 0, tbuf.length);
            if (r <= 0) break;
            onTun(tbuf, r, now);
          }
          flushSend();
        }
      }
      timers(now);
      if (maxPackets > 0 && delivered() >= maxPackets) return;
    }
  }
}
