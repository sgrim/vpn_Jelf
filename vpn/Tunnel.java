/*
 * Copyright © 2018-2026 Diego Fernando Mayor Rojas. Todos los derechos reservados.
 *
 * Este archivo es parte de jelf. Software propietario:
 * queda prohibida su copia, uso, modificación o distribución
 * sin autorización expresa y por escrito del autor. Ver el archivo LICENSE.
 */
/*
 * Tunnel.java - «jvpn up»: un túnel WireGuard de UN par entre una interfaz TUN y un socket UDP, en modo usuario.
 *   TUN → UDP: cada paquete IPv4 cuyo destino esté en las direcciones permitidas del par se cifra y se envía a su punto final (sin sesión vigente se guarda el último paquete y se inicia el apretón de manos).
 *   UDP → TUN: cada mensaje de datos se abre con la sesión actual o la anterior; el paquete interior debe ser IPv4, con largo coherente y ORIGEN dentro de las direcciones permitidas (enrutamiento por clave
 *   criptográfica: sin esto un par autenticado podría suplantar cualquier origen), y entonces se escribe en la TUN. Todo lo que llega por UDP es hostil: nada se escribe en la TUN sin pasar la etiqueta.
 * Se crea la TUN y se enlaza el socket CON privilegios y después se sueltan (--user), antes de leer el primer paquete. Tiempos como WireGuard: renovar la sesión a los 120 s al enviar, no usar una de más de 180 s,
 * reintentar el apretón de manos cada 5 s hasta 3 veces. Límite de iniciaciones procesadas: 20 por segundo (cada una cuesta curvas elípticas; sin cookies, R-V02). IPv4 solamente (V2: IPv6).
 */

public final class Tunnel {
  static final long REKEY_AFTER_MS = 120000;
  static final long REJECT_AFTER_MS = 180000;
  static final long REKEY_TIMEOUT_MS = 5000;
  static final int MAX_ATTEMPTS = 3;
  static final int MAX_INITIATIONS_PER_SEC = 20;

  Handshake hs;
  int udp;
  int tun;
  int peerIp;
  int peerPort;
  boolean haveEndpoint;
  int allowedNet;
  int allowedMask;
  boolean verbose;
  int keepaliveSec;

  Session cur;
  long curSince;
  Session prev;
  boolean handshaking;
  long handshakeSent;
  int attempts;
  byte[] queued;
  int queuedLen;
  long lastSend;
  long secStart;
  int secCount;

  // contadores
  long rxPackets;
  long txPackets;
  long rxDropped;

  void log(String s) {
    if (verbose) System.err.println("jvpn: " + s);
  }

  boolean inAllowed(int ip) {
    return (ip & allowedMask) == allowedNet;
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

  void sendDatagram(byte[] m, int len) {
    if (!haveEndpoint) return;
    Udp.sendTo(udp, peerIp, peerPort, m, 0, len);
  }

  void startHandshake(long now) {
    if (!haveEndpoint) return;
    byte[] m = hs.createInitiation();
    if (m == null) return;
    handshaking = true;
    handshakeSent = now;
    attempts++;
    sendDatagram(m, m.length);
    log("iniciación enviada (intento " + attempts + ")");
  }

  /** Cifra y envía un paquete con la sesión vigente; false si no hay una utilizable. */
  boolean sendPacket(byte[] p, int len, long now) {
    if (cur == null || now - curSince >= REJECT_AFTER_MS) {
      cur = null;
      return false;
    }
    if (cur.initiator && now - curSince >= REKEY_AFTER_MS && !handshaking) {
      attempts = 0;
      startHandshake(now);
    }
    byte[] m = cur.seal(p, len);
    if (m == null) {
      cur = null;
      return false;
    }
    sendDatagram(m, m.length);
    lastSend = now;
    return true;
  }

  void onTun(byte[] buf, int n, long now) {
    int total = ipv4Length(buf, n);
    if (total < 0) {
      rxDropped++;
      return;
    }
    if (!inAllowed(ipAt(buf, 16))) {
      rxDropped++;
      return;
    }
    if (sendPacket(buf, total, now)) {
      txPackets++;
      return;
    }
    // sin sesión: se guarda el último paquete y se inicia el apretón de manos
    queued = new byte[total];
    for (int i = 0; i < total; i++) queued[i] = buf[i];
    queuedLen = total;
    if (!handshaking) {
      attempts = 0;
      startHandshake(now);
    }
  }

  void flushQueue(long now) {
    if (queued != null && cur != null) {
      if (sendPacket(queued, queuedLen, now)) txPackets++;
      queued = null;
    }
  }

  void onUdp(byte[] buf, int n, long now) {
    if (n < 4) return;
    int type = buf[0];
    if (type == 1) {
      if (now - secStart >= 1000) {
        secStart = now;
        secCount = 0;
      }
      if (++secCount > MAX_INITIATIONS_PER_SEC) return; // límite: cada iniciación cuesta varias multiplicaciones de curva
      if (!hs.consumeInitiation(buf, n)) return;
      byte[] r = hs.createResponse();
      if (r == null) return;
      peerIp = Udp.srcIp;
      peerPort = Udp.srcPort;
      haveEndpoint = true;
      sendDatagram(r, r.length);
      prev = cur;
      cur = hs.pending;
      curSince = now;
      handshaking = false;
      log("apretón de manos aceptado (respondedor)");
    } else if (type == 2) {
      Session s = hs.consumeResponse(buf, n);
      if (s == null) return;
      prev = cur;
      cur = s;
      curSince = now;
      handshaking = false;
      attempts = 0;
      log("apretón de manos completo (iniciador)");
      byte[] ka = cur.seal(new byte[0], 0); // el primer mensaje de datos lo manda el iniciador y confirma la sesión
      sendDatagram(ka, ka.length);
      lastSend = now;
      flushQueue(now);
    } else if (type == 4) {
      byte[] pt = null;
      if (cur != null && now - curSince < REJECT_AFTER_MS + 30000) pt = cur.open(buf, n);
      if (pt == null && prev != null) pt = prev.open(buf, n);
      if (pt == null) {
        rxDropped++;
        return;
      }
      peerIp = Udp.srcIp; // itinerancia: solo tras autenticar un mensaje
      peerPort = Udp.srcPort;
      haveEndpoint = true;
      if (pt.length == 0) return; // keepalive
      int total = ipv4Length(pt, pt.length);
      if (total < 0 || !inAllowed(ipAt(pt, 12))) {
        rxDropped++; // origen fuera de las direcciones permitidas: suplantación
        return;
      }
      Tun.write(tun, pt, 0, total);
      rxPackets++;
    }
  }

  void timers(long now) {
    if (cur != null && now - curSince >= REJECT_AFTER_MS) cur = null;
    if (prev != null && now - curSince >= REJECT_AFTER_MS) prev = null;
    if (handshaking && now - handshakeSent >= REKEY_TIMEOUT_MS) {
      if (attempts >= MAX_ATTEMPTS) {
        handshaking = false;
        queued = null;
        log("sin respuesta del par: se abandona el apretón de manos");
      } else {
        startHandshake(now);
      }
    }
    if (keepaliveSec > 0 && haveEndpoint && now - lastSend >= keepaliveSec * 1000L) {
      if (cur != null) {
        byte[] ka = cur.seal(new byte[0], 0);
        if (ka != null) {
          sendDatagram(ka, ka.length);
          lastSend = now;
        }
      } else if (!handshaking) {
        attempts = 0;
        startHandshake(now);
        lastSend = now;
      }
    }
  }

  /** Corre el túnel hasta que se mate el proceso. maxPackets > 0 lo termina tras ese número de paquetes entregados a la TUN (para las pruebas). */
  void run(long maxPackets) {
    Poller poll = new Poller(4);
    poll.add(udp, Net.IN);
    poll.add(tun, Net.IN);
    byte[] ubuf = new byte[4096];
    byte[] tbuf = new byte[65536];
    long now = System.currentTimeMillis();
    if (haveEndpoint) startHandshake(now);
    for (;;) {
      int n = poll.await(1000);
      now = System.currentTimeMillis();
      for (int i = 0; i < n; i++) {
        int fd = poll.fd(i);
        if (fd == udp) {
          for (int k = 0; k < 64; k++) { // se vacía el socket, con tope para no dejar sin atender la TUN
            int r = Udp.recvFrom(udp, ubuf, 0, ubuf.length);
            if (r < 0) break;
            onUdp(ubuf, r, now);
          }
        } else if (fd == tun) {
          for (int k = 0; k < 64; k++) {
            int r = Tun.read(tun, tbuf, 0, tbuf.length);
            if (r <= 0) break;
            onTun(tbuf, r, now);
          }
        }
      }
      timers(now);
      if (maxPackets > 0 && rxPackets >= maxPackets) return;
    }
  }
}
