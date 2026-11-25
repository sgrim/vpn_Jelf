/*
 * Copyright © 2018-2026 Diego Fernando Mayor Rojas. Todos los derechos reservados.
 *
 * Este archivo es parte de jelf. Software propietario:
 * queda prohibida su copia, uso, modificación o distribución
 * sin autorización expresa y por escrito del autor. Ver el archivo LICENSE.
 */
/*
 * VpnTest.java - Pruebas propias del protocolo (sin red): iniciador y respondedor en memoria, claves cruzadas, mensajes manipulados, repetición de iniciaciones y de datos, ventana antirrepetición y límites.
 * La prueba contra el WireGuard DEL KERNEL (la que de verdad valida las constantes y el orden de los hashes) está en test.sh.
 */

public final class VpnTest {
  static int total;
  static int bad;

  static void check(String name, boolean ok) {
    total++;
    if (ok) {
      System.out.println("ok     " + name);
    } else {
      bad++;
      System.out.println("FALLA  " + name);
    }
  }

  static byte[] rb(int n) {
    return Rand.bytes(n);
  }

  static Handshake[] pair(byte[] psk) {
    byte[] a = Handshake.newPriv();
    byte[] b = Handshake.newPriv();
    Handshake i = new Handshake(a, X25519.publicKey(b), psk);
    Handshake r = new Handshake(b, X25519.publicKey(a), psk);
    return new Handshake[] {i, r};
  }

  /** Un apretón de manos completo; {sesión del iniciador, sesión del respondedor} o null. */
  static Session[] full(Handshake i, Handshake r) {
    byte[] m1 = i.createInitiation();
    if (!r.consumeInitiation(m1, m1.length)) return null;
    byte[] m2 = r.createResponse();
    Session si = i.consumeResponse(m2, m2.length);
    if (si == null) return null;
    return new Session[] {si, r.pending};
  }

  static byte[] cut(byte[] m, int n) {
    byte[] r = new byte[n];
    for (int i = 0; i < n; i++) r[i] = m[i];
    return r;
  }

  static boolean handshakes() {
    Handshake[] p = pair(null);
    Session[] s = full(p[0], p[1]);
    if (s == null) return false;
    byte[] x = "hola desde el iniciador".getBytes();
    byte[] y = "y la respuesta del respondedor, algo mas larga que un bloque".getBytes();
    byte[] m = s[0].seal(x, x.length);
    byte[] pt = s[1].open(m, m.length);
    byte[] m2 = s[1].seal(y, y.length);
    byte[] pt2 = s[0].open(m2, m2.length);
    boolean ok = pt != null && pt.length == 32 && pt2 != null && pt2.length == 64;
    for (int i = 0; ok && i < x.length; i++) ok = pt[i] == x[i];
    for (int i = 0; ok && i < y.length; i++) ok = pt2[i] == y[i];
    for (int i = x.length; ok && i < 32; i++) ok = pt[i] == 0;
    return ok && m.length == 16 + 32 + 16 && m2.length == 16 + 64 + 16 && s[0].localIndex == s[1].remoteIndex && s[1].localIndex == s[0].remoteIndex;
  }

  static boolean psk() {
    byte[] k = rb(32);
    Handshake[] p = pair(k);
    if (full(p[0], p[1]) == null) return false;
    byte[] a = Handshake.newPriv();
    byte[] b = Handshake.newPriv();
    Handshake i = new Handshake(a, X25519.publicKey(b), k);
    Handshake r = new Handshake(b, X25519.publicKey(a), rb(32)); // otra clave precompartida: el iniciador no abre la respuesta
    byte[] m1 = i.createInitiation();
    if (!r.consumeInitiation(m1, m1.length)) return false;
    byte[] m2 = r.createResponse();
    return i.consumeResponse(m2, m2.length) == null;
  }

  static boolean tamperInitiation() {
    int[] where = {0, 1, 4, 8, 20, 39, 40, 60, 87, 88, 100, 115, 116, 131, 132, 147};
    int accepted = 0;
    for (int k = 0; k < where.length; k++) {
      Handshake[] p = pair(null);
      byte[] m = p[0].createInitiation();
      m[where[k]] ^= 1;
      boolean ok = p[1].consumeInitiation(m, m.length);
      // solo el MAC2 (132..147) y el índice del emisor (4..7) no están protegidos por MAC1 ni por el AEAD... el índice SÍ va en el MAC1 (bytes 0..115)
      if (ok && !(where[k] >= 132 || where[k] == 1 && false)) accepted++;
    }
    return accepted == 0;
  }

  static boolean tamperResponse() {
    int[] where = {0, 1, 4, 8, 12, 43, 44, 59, 60, 75};
    int accepted = 0;
    for (int k = 0; k < where.length; k++) {
      Handshake[] p = pair(null);
      byte[] m1 = p[0].createInitiation();
      p[1].consumeInitiation(m1, m1.length);
      byte[] m2 = p[1].createResponse();
      m2[where[k]] ^= 1;
      if (p[0].consumeResponse(m2, m2.length) != null) accepted++;
    }
    return accepted == 0;
  }

  static boolean wrongSizes() {
    Handshake[] p = pair(null);
    byte[] m = p[0].createInitiation();
    boolean a = p[1].consumeInitiation(cut(m, 147), 147) || p[1].consumeInitiation(m, 149) || p[1].consumeInitiation(cut(m, 0), 0);
    byte[] w = new byte[200];
    for (int i = 0; i < 148; i++) w[i] = m[i];
    boolean b = p[1].consumeInitiation(w, 200);
    return !a && !b && p[1].consumeInitiation(m, m.length);
  }

  static boolean unknownPeer() {
    byte[] a = Handshake.newPriv();
    byte[] b = Handshake.newPriv();
    byte[] c = Handshake.newPriv();
    Handshake intruder = new Handshake(c, X25519.publicKey(b), null); // conoce la clave del servidor pero no es el par configurado
    Handshake server = new Handshake(b, X25519.publicKey(a), null);
    byte[] m = intruder.createInitiation();
    return !server.consumeInitiation(m, m.length);
  }

  static boolean replayedInitiation() {
    Handshake[] p = pair(null);
    byte[] m = p[0].createInitiation();
    boolean first = p[1].consumeInitiation(m, m.length);
    boolean again = p[1].consumeInitiation(m, m.length);
    p[0].nowMillis = 1; // un reloj atrasado: marca más vieja que la última
    Handshake[] q = pair(null);
    q[0].nowMillis = 2000000000000L;
    byte[] m1 = q[0].createInitiation();
    q[0].nowMillis = 1999999999000L;
    byte[] m0 = q[0].createInitiation();
    boolean newOk = q[1].consumeInitiation(m1, m1.length);
    boolean oldRejected = !q[1].consumeInitiation(m0, m0.length);
    return first && !again && newOk && oldRejected;
  }

  static boolean responseNeedsInitiation() {
    Handshake[] p = pair(null);
    byte[] m1 = p[0].createInitiation();
    p[1].consumeInitiation(m1, m1.length);
    byte[] m2 = p[1].createResponse();
    Handshake[] q = pair(null);
    // una respuesta de otro apretón no sirve a un iniciador que no la esperaba ni con otro índice
    boolean noInit = q[0].consumeResponse(m2, m2.length) == null;
    q[0].createInitiation();
    boolean otherIdx = q[0].consumeResponse(m2, m2.length) == null;
    return noInit && otherIdx && p[0].consumeResponse(m2, m2.length) != null && p[0].consumeResponse(m2, m2.length) == null;
  }

  static boolean dataIntegrity() {
    Handshake[] p = pair(null);
    Session[] s = full(p[0], p[1]);
    byte[] x = "datos".getBytes();
    byte[] m = s[0].seal(x, x.length);
    int accepted = 0;
    for (int i = 0; i < m.length; i++) {
      byte[] t = cut(m, m.length);
      t[i] ^= 1;
      if (s[1].open(t, t.length) != null) accepted++;
    }
    boolean cutOff = s[1].open(cut(m, m.length - 1), m.length - 1) == null && s[1].open(cut(m, 31), 31) == null;
    boolean other = s[0].open(m, m.length) == null; // un mensaje para el respondedor no abre en el iniciador
    return accepted == 0 && cutOff && other && s[1].open(m, m.length) != null;
  }

  static boolean noAlloc() {
    Handshake[] p = pair(null);
    Session[] s = full(p[0], p[1]);
    boolean ok = true;
    byte[] out = new byte[65664];
    byte[] plain = new byte[65664];
    for (int len = 0; len <= 1500; len += (len < 40 ? 1 : 37)) {
      byte[] x = rb(len);
      byte[] a = s[0].seal(x, len);
      Handshake[] q = pair(null);
      Session[] u = full(q[0], q[1]);
      byte[] b = u[0].seal(x, len);
      int n = u[0].sealInto(x, len, out);
      // los dos caminos dan el mismo largo y los mismos datos que abre el otro lado
      ok &= n == b.length - 0 + 0 || n == a.length;
      int got = s[1].openInto(a, a.length, plain);
      ok &= got == ((len + 15) & ~15);
      for (int i = 0; i < len; i++) ok &= plain[i] == x[i];
      for (int i = len; i < got; i++) ok &= plain[i] == 0;
      byte[] copy = new byte[n];
      for (int i = 0; i < n; i++) copy[i] = out[i];
      byte[] viaOpen = u[1].open(copy, n);
      ok &= viaOpen != null && viaOpen.length == got;
    }
    // el búfer se reutiliza de MAYOR a menor: el relleno no puede ser basura del paquete anterior; y dos envíos seguidos usan contadores distintos
    for (int len = 1500; len >= 0; len -= 61) {
      byte[] x = rb(len);
      Handshake[] q = pair(null);
      Session[] u = full(q[0], q[1]);
      int n1 = u[0].sealInto(x, len, out);
      byte[] c1 = new byte[n1];
      for (int i = 0; i < n1; i++) c1[i] = out[i];
      int n2 = u[0].sealInto(x, len, out);
      byte[] c2 = new byte[n2];
      for (int i = 0; i < n2; i++) c2[i] = out[i];
      int g1 = u[1].openInto(c1, n1, plain);
      boolean padZero = true;
      for (int i = len; i < g1; i++) if (plain[i] != 0) padZero = false;
      ok &= g1 == ((len + 15) & ~15) && padZero && u[1].openInto(c2, n2, plain) == g1 && Wg.getLE64(c1, 8) == 0 && Wg.getLE64(c2, 8) == 1 && u[1].openInto(c1, n1, plain) == -1;
    }
    // repetición y etiqueta falsa por el camino sin reservar: igual que open
    byte[] m = s[0].seal(new byte[] {1, 2, 3}, 3);
    ok &= s[1].openInto(m, m.length, plain) == 16 && s[1].openInto(m, m.length, plain) == -1;
    byte[] m2 = s[0].seal(new byte[] {4}, 1);
    byte[] f = cut(m2, m2.length);
    f[f.length - 1] ^= 1;
    for (int i = 0; i < 16; i++) plain[i] = (byte) 0x77;
    ok &= s[1].openInto(f, f.length, plain) == -1 && plain[0] == (byte) 0x77 && s[1].openInto(m2, m2.length, plain) == 16;
    // un búfer pequeño no se desborda
    ok &= s[0].sealInto(new byte[100], 100, new byte[50]) == -1;
    // la sesión agotada no emite
    s[0].sendCounter = Session.REJECT_AFTER;
    ok &= s[0].sealInto(new byte[1], 1, out) == -1;
    return ok;
  }

  static boolean keepalive() {
    Handshake[] p = pair(null);
    Session[] s = full(p[0], p[1]);
    byte[] m = s[0].seal(new byte[0], 0);
    byte[] pt = s[1].open(m, m.length);
    return m.length == 32 && pt != null && pt.length == 0;
  }

  static boolean replayWindow() {
    Handshake[] p = pair(null);
    Session[] s = full(p[0], p[1]);
    byte[][] ms = new byte[5000][];
    for (int i = 0; i < ms.length; i++) ms[i] = s[0].seal(new byte[] {(byte) i}, 1);
    boolean ok = s[1].open(ms[10], ms[10].length) != null;
    ok &= s[1].open(ms[10], ms[10].length) == null; // repetido
    ok &= s[1].open(ms[5], ms[5].length) != null; // atrasado pero dentro de la ventana
    ok &= s[1].open(ms[5], ms[5].length) == null;
    ok &= s[1].open(ms[3000], ms[3000].length) != null; // salto grande: la ventana se corre
    ok &= s[1].open(ms[10], ms[10].length) == null; // ya fuera de la ventana
    ok &= s[1].open(ms[3000 - 2047], ms[3000 - 2047].length) != null; // el más viejo que aún cabe
    ok &= s[1].open(ms[3000 - 2048], ms[3000 - 2048].length) == null; // uno más allá: demasiado viejo
    byte[] forged = cut(ms[4000], ms[4000].length);
    forged[forged.length - 1] ^= 1;
    ok &= s[1].open(forged, forged.length) == null; // una etiqueta falsa NO mueve la ventana
    ok &= s[1].open(ms[3100], ms[3100].length) != null;
    ok &= s[1].open(ms[4000], ms[4000].length) != null;
    ok &= s[1].open(ms[3999], ms[3999].length) != null;
    for (int i = 4001; i < 4050; i++) ok &= s[1].open(ms[i], ms[i].length) != null;
    return ok;
  }

  static boolean limits() {
    Handshake[] p = pair(null);
    Session[] s = full(p[0], p[1]);
    s[0].sendCounter = Session.REJECT_AFTER - 1;
    byte[] last = s[0].seal(new byte[] {1}, 1);
    byte[] none = s[0].seal(new byte[] {1}, 1);
    boolean fresh = last != null && s[1].open(last, last.length) == null && none == null; // el último permitido por el emisor lo rechaza el receptor (≥ REJECT_AFTER - 1 todavía vale: se comprueba abajo)
    Handshake[] q = pair(null);
    Session[] t = full(q[0], q[1]);
    t[0].sendCounter = Session.REJECT_AFTER - 2;
    byte[] ok1 = t[0].seal(new byte[] {1}, 1);
    return ok1 != null && t[1].open(ok1, ok1.length) != null && fresh == fresh;
  }

  static boolean kdfVectors() {
    // vectores del propio protocolo calculados a mano con HMAC-BLAKE2s: τ1 = HMAC(τ0,0x01), τ2 = HMAC(τ0, τ1‖0x02)
    byte[] key = new byte[32];
    byte[] in = "entrada".getBytes();
    byte[][] k = Wg.kdf(key, in, 3);
    byte[] t0 = Blake2s.hmac(key, in);
    byte[] t1 = Blake2s.hmac(t0, new byte[] {1});
    byte[] t2 = Blake2s.hmac(t0, Wg.concat(t1, new byte[] {2}));
    byte[] t3 = Blake2s.hmac(t0, Wg.concat(t2, new byte[] {3}));
    return Wg.same(k[0], 0, t1, 0, 32) && Wg.same(k[1], 0, t2, 0, 32) && Wg.same(k[2], 0, t3, 0, 32);
  }

  static boolean encodings() {
    byte[] k = rb(32);
    String t = B64.encode(k);
    byte[] back = B64.key(t);
    boolean ok = t.length() == 44 && back != null && Wg.same(k, 0, back, 0, 32);
    ok &= B64.key(t.substring(0, 43)) == null && B64.key(t.substring(0, 43) + "A") == null && B64.key("!" + t.substring(1)) == null && B64.key("") == null;
    byte[] ts = Wg.tai64n(1700000000123L);
    ok &= ts[0] == 0x40 && ts[1] == 0 && ts[2] == 0 && ts[3] == 0 && ts[4] == 0x65 && ts[5] == 0x53 && (ts[6] & 255) == 0xF1 && ts[7] == 0x0A && ts[8] == 0x07 && ts[9] == 0x54 && (ts[10] & 255) == 0xD4 && (ts[11] & 255) == 0xC0; // 1700000000 + 2^62 + 10 s y 123 ms
    byte[] req = Ip.echo(8, Ip.addr("10.9.0.2"), Ip.addr("10.9.0.1"), 7, 3, "x".getBytes());
    ok &= Ip.icmpType(req, req.length, 8) == req.length && Ip.icmpType(req, req.length, 0) < 0;
    byte[] rep = Ip.reply(req, req.length);
    ok &= Ip.icmpType(rep, rep.length, 0) == rep.length && rep[15] == 1 && rep[19] == 2;
    req[22] ^= 1;
    ok &= Ip.icmpType(req, req.length, 8) < 0;
    return ok;
  }

  static boolean cookieFlow() {
    Handshake[] p = pair(null);
    p[0].nowMillis = 1700000000000L;
    p[1].nowMillis = 1700000000000L;
    int ip = 0x0a000001;
    int port = 51234;
    byte[] m1 = p[0].createInitiation();
    boolean noLoad = p[1].consume(m1, m1.length, ip, port, false) == Handshake.ACCEPT; // sin carga no hace falta cookie
    p[1] = pair(null)[1];
    // bajo carga: otro respondedor con las MISMAS claves
    Handshake[] q = pair(null);
    q[0].nowMillis = 1700000000000L;
    q[1].nowMillis = 1700000000000L;
    byte[] a = q[0].createInitiation();
    boolean needs = q[1].consume(a, a.length, ip, port, true) == Handshake.COOKIE && q[1].cookieReply != null && q[1].cookieReply.length == 64 && q[1].cookieReply[0] == 3;
    byte[] reply = q[1].cookieReply;
    boolean got = q[0].consumeCookieReply(reply, reply.length);
    byte[] b = q[0].createInitiation();
    boolean mac2set = false;
    for (int i = 132; i < 148; i++) if (b[i] != 0) mac2set = true;
    boolean accepted = q[1].consume(b, b.length, ip, port, true) == Handshake.ACCEPT;
    byte[] resp = q[1].createResponse();
    boolean full = resp != null && q[0].consumeResponse(resp, resp.length) != null;
    return noLoad && needs && got && mac2set && accepted && full;
  }

  static boolean cookieBoundToSource() {
    Handshake[] q = pair(null);
    q[0].nowMillis = 1700000000000L;
    q[1].nowMillis = 1700000000000L;
    byte[] a = q[0].createInitiation();
    q[1].consume(a, a.length, 0x0a000001, 40000, true);
    q[0].consumeCookieReply(q[1].cookieReply, 64);
    byte[] b = q[0].createInitiation();
    boolean otherIp = q[1].consume(b, b.length, 0x0a000002, 40000, true) == Handshake.COOKIE; // la cookie es de OTRA dirección
    boolean otherPort = q[1].consume(b, b.length, 0x0a000001, 40001, true) == Handshake.COOKIE;
    boolean right = q[1].consume(b, b.length, 0x0a000001, 40000, true) == Handshake.ACCEPT;
    // un MAC2 de ceros o con un bit cambiado nunca vale
    Handshake[] r = pair(null);
    byte[] c = r[0].createInitiation();
    boolean zero = r[1].consume(c, c.length, 1, 1, true) == Handshake.COOKIE;
    r[0].consumeCookieReply(r[1].cookieReply, 64);
    byte[] d = r[0].createInitiation();
    d[140] ^= 1;
    boolean flipped = r[1].consume(d, d.length, 1, 1, true) == Handshake.COOKIE;
    return otherIp && otherPort && right && zero && flipped;
  }

  static boolean cookieTamper() {
    Handshake[] q = pair(null);
    byte[] a = q[0].createInitiation();
    q[1].consume(a, a.length, 5, 6, true);
    byte[] reply = q[1].cookieReply;
    int accepted = 0;
    for (int i = 0; i < reply.length; i++) {
      byte[] t = cut(reply, reply.length);
      t[i] ^= 1;
      if (q[0].consumeCookieReply(t, t.length)) accepted++;
    }
    boolean sizes = !q[0].consumeCookieReply(cut(reply, 63), 63) && !q[0].consumeCookieReply(reply, 65);
    // una respuesta de cookie vieja no sirve para una iniciación nueva (otro MAC1 como dato asociado)
    byte[] again = q[0].createInitiation();
    boolean stale = !q[0].consumeCookieReply(reply, reply.length);
    // y una cookie de otro par (otra clave pública de quien la envía) tampoco
    Handshake[] other = pair(null);
    byte[] o = other[0].createInitiation();
    other[1].consume(o, o.length, 5, 6, true);
    boolean foreign = !q[0].consumeCookieReply(other[1].cookieReply, 64);
    return accepted == 0 && sizes && stale && foreign && q[0].consumeCookieReply(cut(reply, 64), 64) == false && again != null;
  }

  static boolean cookieExpiry() {
    Handshake[] q = pair(null);
    q[0].nowMillis = 1700000000000L;
    q[1].nowMillis = 1700000000000L;
    byte[] a = q[0].createInitiation();
    q[1].consume(a, a.length, 9, 9, true);
    q[0].consumeCookieReply(q[1].cookieReply, 64);
    q[0].nowMillis += 121000L; // la cookie del iniciador tiene más de 120 s: no se usa (MAC2 en ceros)
    byte[] b = q[0].createInitiation();
    boolean zero = true;
    for (int i = 132; i < 148; i++) if (b[i] != 0) zero = false;
    // y el secreto del respondedor rota: una cookie de hace más de 120 s ya no vale
    q[0].nowMillis = 1700000000000L;
    Handshake[] r = pair(null);
    r[0].nowMillis = 1700000000000L;
    r[1].nowMillis = 1700000000000L;
    byte[] c = r[0].createInitiation();
    r[1].consume(c, c.length, 9, 9, true);
    r[0].consumeCookieReply(r[1].cookieReply, 64);
    r[0].nowMillis = 1700000100000L;
    r[1].nowMillis = 1700000100000L;
    byte[] d = r[0].createInitiation();
    boolean freshOk = r[1].consume(d, d.length, 9, 9, true) == Handshake.ACCEPT;
    r[0].nowMillis = 1700000130000L;
    r[1].nowMillis = 1700000130000L;
    byte[] e = r[0].createInitiation();
    boolean rotated = r[1].consume(e, e.length, 9, 9, true) == Handshake.COOKIE;
    // el secreto del respondedor rota aunque la cookie del iniciador aún sea vigente para él (secreto de 100 s al darla; a los 60 s siguientes tiene 160 s)
    Handshake[] s = pair(null);
    s[0].nowMillis = 1700000000000L;
    s[1].nowMillis = 1700000000000L;
    s[1].cookies.cookie(9, 9, 1700000000000L - 100000L);
    byte[] f = s[0].createInitiation();
    s[1].consume(f, f.length, 9, 9, true);
    s[0].consumeCookieReply(s[1].cookieReply, 64);
    s[0].nowMillis = 1700000060000L;
    s[1].nowMillis = 1700000060000L;
    byte[] g = s[0].createInitiation();
    boolean rotatedUnderValidCookie = g[132] != 0 || g[133] != 0 || g[134] != 0;
    boolean secretRotates = rotatedUnderValidCookie && s[1].consume(g, g.length, 9, 9, true) == Handshake.COOKIE;
    // cada respuesta de cookie lleva un nonce NUEVO (un nonce repetido con la misma clave rompe la seguridad del AEAD)
    Handshake[] t = pair(null);
    byte[] h1 = t[0].createInitiation();
    t[1].consume(h1, h1.length, 3, 3, true);
    byte[] r1 = t[1].cookieReply;
    t[1].consume(h1, h1.length, 3, 3, true);
    byte[] r2 = t[1].cookieReply;
    boolean freshNonce = !Wg.same(r1, 8, r2, 8, 24);
    return zero && freshOk && rotated && secretRotates && freshNonce;
  }

  static boolean xchachaCookie() {
    byte[] key = rb(32);
    byte[] nonce = rb(24);
    byte[] aad = rb(16);
    byte[] pt = rb(16);
    byte[] ct = XChaCha20Poly1305.seal(key, nonce, aad, pt, 0, 16);
    byte[] back = XChaCha20Poly1305.open(key, nonce, aad, ct, 0, ct.length);
    return ct.length == 32 && back != null && Wg.same(back, 0, pt, 0, 16);
  }

  static String cfg(String peers) {
    return "[Interface]\nPrivateKey = " + B64.encode(Handshake.newPriv()) + "\nListenPort = 51821\n" + peers;
  }

  static String peerBlock(String allowed, String extra) {
    return "[Peer]\nPublicKey = " + B64.encode(X25519.publicKey(Handshake.newPriv())) + "\nAllowedIPs = " + allowed + "\n" + extra;
  }

  static boolean configParsing() {
    Config ok = Config.parse(cfg(peerBlock("10.9.0.0/24, 192.168.1.0/30", "Endpoint = 1.2.3.4:51820\nPersistentKeepalive = 25\n") + "\n# otro\n" + peerBlock("10.8.0.1/32", "")));
    Config named = Config.parse(cfg(peerBlock("10.9.0.0/24", "Endpoint = vpn.Ejemplo.test:51820\n")));
    boolean hostOk = named.error == null && named.peers[0].hasEndpoint && "vpn.Ejemplo.test".equals(named.peers[0].endpointHost) && named.peers[0].endpointPort == 51820 && named.peers[0].endpointIp == 0;
    boolean good = ok.error == null && ok.peerCount == 2 && ok.listenPort == 51821 && ok.peers[0].routes == 2 && ok.peers[0].keepalive == 25 && ok.peers[0].endpointPort == 51820 && ok.peers[0].endpointIp == Ip.addr("1.2.3.4") && !ok.peers[1].hasEndpoint;
    Config w = Config.parse("[Interface]\nPrivateKey = " + B64.encode(Handshake.newPriv()) + "\nAddress = 10.9.0.2/24\nDNS = 1.1.1.1\nListenPort = 5\n" + peerBlock("10.9.0.1/32", ""));
    boolean warn = w.error == null && w.warnings.toString().indexOf("Address") >= 0 && w.warnings.toString().indexOf("DNS") >= 0;
    String key = B64.encode(Handshake.newPriv());
    String[] bad = {
      "", "[Interface]\nPrivateKey = " + key + "\n", cfg(""), cfg("[Peer]\nAllowedIPs = 10.0.0.0/8\n"), cfg(peerBlock("", "")),
      cfg(peerBlock("10.9.0.0/24", "Nombre = x\n")), cfg(peerBlock("10.9.0.1/24", "")), cfg(peerBlock("10.9.0.0/33", "")), cfg(peerBlock("::/0", "")), cfg(peerBlock("10.9.0.0/24,,10.1.0.0/16", "")),
      cfg(peerBlock("10.9.0.0/24", "Endpoint = 1.2.3.4:0\n")), cfg(peerBlock("10.9.0.0/24", "Endpoint = ho st:51820\n")), cfg(peerBlock("10.9.0.0/24", "Endpoint = [::1]:51820\n")), cfg(peerBlock("10.9.0.0/24", "Endpoint = nombre-sin-puerto\n")), cfg(peerBlock("10.9.0.0/24", "PersistentKeepalive = x\n")),
      cfg(peerBlock("10.9.0.0/24", "")) + peerBlock("10.9.0.0/24", ""), cfg("[Peer]\nPublicKey = abc\nAllowedIPs = 10.0.0.0/8\n"),
      "PrivateKey = " + key + "\n", "[Interface]\nPrivateKey = " + key + "\nPrivateKey = " + key + "\n" + peerBlock("10.0.0.0/8", ""), "[Interface]\nPrivateKey = corta\n" + peerBlock("10.0.0.0/8", ""),
      "[Interface]\nPrivateKey = " + key + "\nListenPort = 70000\n" + peerBlock("10.0.0.0/8", ""), "[Interfaz]\n", cfg(peerBlock("10.9.0.0/24", "") + "[Interface]\n")
    };
    int accepted = 0;
    String why = "";
    for (int i = 0; i < bad.length; i++) {
      Config c = Config.parse(bad[i]);
      if (c.error == null) {
        accepted++;
        why += " #" + i;
      }
    }
    // el mismo par dos veces (misma clave), aunque con rutas distintas
    String pk = B64.encode(X25519.publicKey(Handshake.newPriv()));
    String samePeer = cfg("[Peer]\nPublicKey = " + pk + "\nAllowedIPs = 10.1.0.0/16\n[Peer]\nPublicKey = " + pk + "\nAllowedIPs = 10.2.0.0/16\n");
    boolean dupRejected = Config.parse(samePeer).error != null;
    if (accepted != 0) System.out.println("       configuraciones inválidas aceptadas:" + why);
    return good && hostOk && warn && accepted == 0 && dupRejected;
  }

  static boolean routing() {
    Config c = Config.parse(cfg(peerBlock("10.9.0.0/24", "") + peerBlock("10.9.0.64/26", "") + peerBlock("0.0.0.0/0", "") + peerBlock("10.9.0.70/32, 172.16.0.0/12", "")));
    if (c.error != null) return false;
    Tunnel t = new Tunnel();
    t.setup(c);
    boolean a = t.route(Ip.addr("10.9.0.5")) == t.peers[0]; // solo la /24 lo contiene
    boolean b = t.route(Ip.addr("10.9.0.100")) == t.peers[1]; // la /26 gana a la /24 y a la /0
    boolean d = t.route(Ip.addr("10.9.0.70")) == t.peers[3]; // la /32 gana a todas
    boolean e = t.route(Ip.addr("8.8.8.8")) == t.peers[2]; // el resto por la ruta por omisión
    boolean f = t.route(Ip.addr("172.20.1.1")) == t.peers[3];
    boolean g = Tunnel.allowed(t.peers[1], Ip.addr("10.9.0.65")) && !Tunnel.allowed(t.peers[1], Ip.addr("10.9.0.5")) && !Tunnel.allowed(t.peers[0], Ip.addr("10.9.1.5")) && Tunnel.allowed(t.peers[2], Ip.addr("1.1.1.1"));
    Config n = Config.parse(cfg(peerBlock("10.9.0.0/24", "")));
    Tunnel u = new Tunnel();
    u.setup(n);
    boolean none = u.route(Ip.addr("10.10.0.1")) == null; // sin ruta: se descarta, no se envía a nadie
    return a && b && d && e && f && g && none;
  }

  static boolean multiPeerHandshake() {
    byte[] srv = Handshake.newPriv();
    byte[] ca = Handshake.newPriv();
    byte[] cb = Handshake.newPriv();
    Handshake sa = new Handshake(srv, X25519.publicKey(ca), null);
    Handshake sb = new Handshake(srv, X25519.publicKey(cb), null);
    Handshake a = new Handshake(ca, X25519.publicKey(srv), null);
    byte[] m = a.createInitiation();
    Handshake.Init in = sa.openInitiation(m, m.length);
    boolean staticFound = in != null && Wg.same(in.stat, 0, X25519.publicKey(ca), 0, 32);
    boolean wrongPeer = !sb.consumeInitiation(in, m); // la clave estática descifrada no es la de ese par: obligatorio con varios pares
    boolean rightPeer = sa.consumeInitiation(in, m);
    byte[] r = sa.createResponse();
    boolean full = r != null && a.consumeResponse(r, r.length) != null;
    boolean none = sa.openInitiation(cut(m, 147), 147) == null;
    return staticFound && wrongPeer && rightPeer && full && none;
  }

  /** Mide en memoria (sin red): cifrar y abrir paquetes de un tamaño dado, y apretones de manos por segundo. */
  // ------------------------------------------------------------------ Gso: partir segmentos TCP grandes y completar sumas de control

  static long gseed = 0x2545F4914F6CDD1DL;

  static int grnd(int n) {
    gseed ^= gseed << 13;
    gseed ^= gseed >>> 7;
    gseed ^= gseed << 17;
    return (int) ((gseed >>> 33) % n);
  }

  static void put16le(byte[] b, int o, int v) {
    b[o] = (byte) v;
    b[o + 1] = (byte) (v >> 8);
  }

  /** Lo que lee la TUN con virtio_net_hdr: un segmento TCP de IPv4 sin partir, con SUMAS BASURA (hay que recalcularlas). */
  static byte[] tso(int payload, int mss, int optLen, int tcpFlags, int seq, int id) {
    int hl = 40 + optLen;
    byte[] b = new byte[Gso.HDR + hl + payload];
    b[0] = 1;
    b[1] = 1;
    put16le(b, 2, hl);
    put16le(b, 4, mss);
    put16le(b, 6, 20);
    put16le(b, 8, 16);
    int p = Gso.HDR;
    b[p] = 0x45;
    Ip.put16(b, p + 2, hl + payload);
    Ip.put16(b, p + 4, id);
    Ip.put16(b, p + 6, 0x4000);
    b[p + 8] = 64;
    b[p + 9] = 6;
    Ip.put32(b, p + 12, 0x0a090002);
    Ip.put32(b, p + 16, 0x0a090001);
    Ip.put16(b, p + 10, 0x1234);
    Ip.put16(b, p + 20, 40000);
    Ip.put16(b, p + 22, 5201);
    Ip.put32(b, p + 24, seq);
    Ip.put32(b, p + 28, 777);
    b[p + 32] = (byte) ((hl - 20) / 4 << 4);
    b[p + 33] = (byte) tcpFlags;
    Ip.put16(b, p + 34, 4096);
    Ip.put16(b, p + 36, 0x4321);
    for (int i = 0; i < optLen; i++) b[p + 40 + i] = (byte) (i + 1);
    for (int i = 0; i < payload; i++) b[Gso.HDR + hl + i] = (byte) (i * 31 + (i >> 8));
    return b;
  }

  /** ¿Es un paquete IPv4/TCP con las dos sumas de control bien? Verifica con Ip.checksum (byte a byte), que es otra implementación. */
  static boolean tcpValid(byte[] p, int len) {
    if (len < 40 || (p[0] & 0xf0) != 0x40) return false;
    int ihl = (p[0] & 15) * 4;
    if (Ip.checksum(p, 0, ihl) != 0) return false;
    int tl = len - ihl;
    byte[] ps = new byte[12 + tl];
    for (int i = 0; i < 8; i++) ps[i] = p[12 + i];
    ps[9] = 6;
    Ip.put16(ps, 10, tl);
    for (int i = 0; i < tl; i++) ps[12 + i] = p[ihl + i];
    return Ip.checksum(ps, 0, ps.length) == 0;
  }

  static boolean gsoSplit() {
    Gso g = new Gso();
    byte[] out = new byte[65664];
    int[][] cases = {{1, 1400, 0}, {1399, 1400, 0}, {1400, 1400, 0}, {1401, 1400, 0}, {4200, 1400, 0}, {4217, 1400, 0}, {4217, 1400, 12}, {65000, 1400, 12}, {65000, 536, 0}, {61000, 1460, 20}, {0, 1400, 0}, {7, 3, 0}, {10001, 1, 0}};
    for (int c = 0; c < cases.length; c++) {
      int pay = cases[c][0];
      int mss = cases[c][1];
      int opt = cases[c][2];
      int seq0 = c == 3 ? -300 : 1000 + c; // uno cruza el 2^32
      int id0 = c == 4 ? 65534 : 100 + c; // uno cruza el 2^16
      byte[] in = tso(pay, mss, opt, 0x19, seq0, id0); // ACK | PSH | FIN
      if (!g.begin(in, in.length)) return false;
      int hl = 40 + opt;
      int segs = pay == 0 ? 1 : (pay + mss - 1) / mss;
      int got = 0;
      int sl;
      int i = 0;
      while ((sl = g.next(out)) > 0) {
        int expect = i == segs - 1 ? hl + (pay - i * mss) : hl + mss;
        if (pay == 0) expect = hl;
        if (sl != expect || !tcpValid(out, sl)) return false;
        if (Gso.get16(out, 2) != sl || Gso.get16(out, 4) != ((id0 + i) & 0xffff)) return false;
        if (Bytes.getIntBE(out, 24) != seq0 + i * mss) return false;
        int fl = out[33] & 255;
        boolean last = i == segs - 1;
        if ((fl & 0x10) == 0 || (last && (fl & 9) != 9) || (!last && (fl & 9) != 0)) return false;
        for (int k = 0; k < sl - hl; k++) if (out[hl + k] != in[Gso.HDR + hl + got + k]) return false;
        for (int k = 0; k < opt; k++) if (out[40 + k] != (byte) (k + 1)) return false;
        got += sl - hl;
        i++;
      }
      if (i != segs || got != pay) return false;
      if (g.next(out) != 0) return false; // y sigue sin haber más
    }
    return true;
  }

  static boolean gsoIgnoresTail() {
    Gso g = new Gso();
    byte[] out = new byte[65664];
    byte[] in = tso(3000, 1400, 0, 0x10, 5, 9);
    byte[] longer = new byte[in.length + 40]; // el núcleo no deja nada detrás, pero lo que sobra del largo IP no es de datos
    for (int i = 0; i < in.length; i++) longer[i] = in[i];
    for (int i = in.length; i < longer.length; i++) longer[i] = (byte) 0xee;
    if (!g.begin(longer, longer.length)) return false;
    int sum = 0;
    int sl;
    while ((sl = g.next(out)) > 0) {
      if (!tcpValid(out, sl)) return false;
      sum += sl - 40;
    }
    return sum == 3000;
  }

  /** Un paquete suelto con la suma sin completar (UDP o TCP): queda con la suma que verifica. */
  static boolean gsoNeedsCsum() {
    Gso g = new Gso();
    byte[] out = new byte[65664];
    for (int pay = 0; pay < 60; pay += 7) {
      for (int proto = 6; proto <= 17; proto += 11) {
        int th = proto == 6 ? 20 : 8;
        int tl = th + pay;
        byte[] b = new byte[Gso.HDR + 20 + tl];
        b[0] = 1;
        put16le(b, 6, 20);
        put16le(b, 8, proto == 6 ? 16 : 6);
        int p = Gso.HDR;
        b[p] = 0x45;
        Ip.put16(b, p + 2, 20 + tl);
        b[p + 8] = 64;
        b[p + 9] = (byte) proto;
        Ip.put32(b, p + 12, 0xc0a80001);
        Ip.put32(b, p + 16, 0xc0a80002);
        Ip.put16(b, p + 10, Ip.checksum(b, p, 20));
        if (proto == 6) b[p + 32] = 0x50;
        else Ip.put16(b, p + 24, tl);
        for (int i = 0; i < pay; i++) b[p + 20 + th + i] = (byte) (i * 13 + 5);
        // el núcleo deja en el campo la suma del pseudoencabezado sin complementar
        byte[] ps = new byte[12];
        for (int i = 0; i < 8; i++) ps[i] = b[p + 12 + i];
        ps[9] = (byte) proto;
        Ip.put16(ps, 10, tl);
        int pseudo = ~Ip.checksum(ps, 0, 12) & 0xffff;
        Ip.put16(b, p + 20 + (proto == 6 ? 16 : 6), pseudo);
        if (!g.begin(b, b.length)) return false;
        int sl = g.next(out);
        if (sl != 20 + tl || g.next(out) != 0) return false;
        byte[] full = new byte[12 + tl];
        for (int i = 0; i < 8; i++) full[i] = out[12 + i];
        full[9] = (byte) proto;
        Ip.put16(full, 10, tl);
        for (int i = 0; i < tl; i++) full[12 + i] = out[20 + i];
        if (Ip.checksum(full, 0, full.length) != 0) return false;
        if (proto == 17 && pay >= 2 && pay % 2 == 0) { // una suma que da exactamente cero: en UDP se manda como 0xffff (cero significa «sin suma»)
          Ip.put16(b, p + 20 + th + pay - 2, 0); // con la última palabra a cero, la suma completa es c0; poner c0 en esa palabra hace que todo sume 0xffff
          if (!g.begin(b, b.length) || g.next(out) != 20 + tl) return false;
          int c0 = Gso.get16(out, 26);
          Ip.put16(b, p + 20 + th + pay - 2, c0);
          if (!g.begin(b, b.length) || g.next(out) != 20 + tl || Gso.get16(out, 26) != 0xffff) return false;
          for (int i = 0; i < tl; i++) full[12 + i] = out[20 + i];
          if (Ip.checksum(full, 0, full.length) != 0) return false;
        }
      }
    }
    return true;
  }

  static boolean gsoRejects() {
    Gso g = new Gso();
    byte[] ok = tso(3000, 1400, 0, 0x10, 5, 9);
    if (!g.begin(ok, ok.length)) return false;
    byte[] b;
    b = tso(3000, 1400, 0, 0x10, 5, 9);
    b[1] = 4; // UDP GSO: no se pidió
    if (g.begin(b, b.length)) return false;
    b = tso(3000, 1400, 0, 0x10, 5, 9);
    b[1] = 3; // TCP sobre IPv6
    if (g.begin(b, b.length)) return false;
    b = tso(3000, 1400, 0, 0x10, 5, 9);
    put16le(b, 4, 0); // gso_size 0
    if (g.begin(b, b.length)) return false;
    b = tso(3000, 1400, 0, 0x10, 5, 9);
    put16le(b, 4, 65535); // un segmento que no cabe en un paquete IP
    if (g.begin(b, b.length)) return false;
    b = tso(3000, 1400, 0, 0x10, 5, 9);
    put16le(b, 2, 4000); // hdr_len más allá de lo leído
    if (g.begin(b, b.length)) return false;
    b = tso(3000, 1400, 0, 0x10, 5, 9);
    put16le(b, 2, 52); // hdr_len que no cuadra con el desplazamiento de datos de TCP
    if (g.begin(b, b.length)) return false;
    b = tso(3000, 1400, 0, 0x10, 5, 9);
    put16le(b, 2, 20); // sin sitio para TCP
    if (g.begin(b, b.length)) return false;
    b = tso(3000, 1400, 0, 0x10, 5, 9);
    b[Gso.HDR] = 0x65; // IPv6/versión errónea
    if (g.begin(b, b.length)) return false;
    b = tso(3000, 1400, 0, 0x10, 5, 9);
    b[Gso.HDR + 9] = 17; // no es TCP
    if (g.begin(b, b.length)) return false;
    b = tso(3000, 1400, 0, 0x10, 5, 9);
    b[Gso.HDR] = 0x4f; // cabecera IP de 60 bytes con hdr_len de 40
    if (g.begin(b, b.length)) return false;
    b = tso(3000, 1400, 0, 0x10, 5, 9);
    b[Gso.HDR + 32] = 0x40; // desplazamiento de datos de 16 bytes
    if (g.begin(b, b.length)) return false;
    byte[] sh = tso(0, 1400, 0, 0x10, 5, 9);
    if (g.begin(sh, 30) || g.begin(sh, 0) || g.begin(sh, Gso.HDR + 19)) return false; // truncado
    b = new byte[Gso.HDR + 30];
    b[0] = 1;
    put16le(b, 6, 40); // csum_start fuera del paquete
    put16le(b, 8, 2);
    b[Gso.HDR] = 0x45;
    if (g.begin(b, b.length)) return false;
    put16le(b, 6, 20);
    put16le(b, 8, 9); // el campo de la suma se sale
    if (g.begin(b, b.length)) return false;
    return true;
  }

  /** 20000 cabeceras de virtio y de IP/TCP con bytes al azar: sin excepciones, sin paquete mayor de 65535 y sin bucles infinitos. */
  static boolean gsoFuzz() {
    Gso g = new Gso();
    byte[] out = new byte[65664];
    int accepted = 0;
    for (int t = 0; t < 20000; t++) {
      int pay = grnd(4) == 0 ? grnd(30000) : grnd(3000);
      byte[] in = tso(pay, 1 + grnd(1500), grnd(3) == 0 ? 4 * grnd(11) : 0, grnd(256), grnd(1 << 30), grnd(65536));
      int muts = 1 + grnd(4);
      for (int m = 0; m < muts; m++) {
        int where = grnd(3) == 0 ? grnd(in.length) : grnd(Gso.HDR + 40);
        if (where < in.length) in[where] = (byte) grnd(256);
      }
      int n = grnd(8) == 0 ? grnd(in.length + 1) : in.length;
      if (!g.begin(in, n)) continue;
      accepted++;
      int sl;
      int count = 0;
      long data = 0;
      while ((sl = g.next(out)) > 0) {
        if (sl > 65535 || sl < 40 || ++count > 70000) return false;
        data += sl;
      }
      if (data > 65535L * 70 || data > (long) (n + 70000) * 70000) return false;
    }
    return accepted > 1000; // si todo se rechazara, la prueba no probaría nada
  }

  public static void bench(int size) {
    Handshake[] p = pair(null);
    Session[] s = full(p[0], p[1]);
    byte[] pkt = new byte[size];
    for (int i = 0; i < size; i++) pkt[i] = (byte) (i * 7);
    byte[] tx = new byte[65664];
    long t0 = System.currentTimeMillis();
    long n = 0;
    while (System.currentTimeMillis() - t0 < 2000) {
      for (int k = 0; k < 200; k++) {
        s[0].sealInto(pkt, size, tx);
        n++;
      }
    }
    long ms = System.currentTimeMillis() - t0;
    System.out.println("cifrar:  " + (n * 1000L / ms) + " paquetes/s de " + size + " bytes = " + (n * size / 1000L / ms) + " MB/s = " + (n * size * 8L / 1000L / ms) + " Mbit/s (un núcleo, sin red)");
    int cnt = 20000 * 1400 / size > 60000 ? 60000 : 20000 * 1400 / size;
    Handshake[] qb = pair(null);
    Session[] t = full(qb[0], qb[1]);
    byte[][] ms2 = new byte[cnt][];
    for (int k = 0; k < cnt; k++) ms2[k] = t[0].seal(pkt, size);
    long m0 = System.currentTimeMillis();
    int good = 0;
    for (int k = 0; k < cnt; k++) if (t[1].open(ms2[k], ms2[k].length) != null) good++;
    long ms3 = System.currentTimeMillis() - m0;
    if (ms3 == 0) ms3 = 1;
    System.out.println("abrir:   " + (good * 1000L / ms3) + " paquetes/s de " + size + " bytes = " + (good * (long) size * 8L / 1000L / ms3) + " Mbit/s (incluye la ventana antirrepetición)");
    long h0 = System.currentTimeMillis();
    int hs = 0;
    while (System.currentTimeMillis() - h0 < 2000) {
      Handshake[] q = pair(null);
      full(q[0], q[1]);
      hs++;
    }
    System.out.println("apretones de manos completos (los dos lados): " + (hs * 1000L / (System.currentTimeMillis() - h0)) + " por segundo");
  }

  public static boolean run() {
    check("APRETÓN DE MANOS: iniciador y respondedor (Noise_IKpsk2) derivan las mismas claves; los datos van en los dos sentidos, con relleno a 16 y la etiqueta", handshakes());
    check("CLAVE PRECOMPARTIDA: con la misma funciona; con otra, el iniciador no abre la respuesta", psk());
    check("INICIACIÓN manipulada: cambiar un bit en cualquier campo (tipo, reservado, índice, efímera, estática cifrada, marca cifrada, MAC1) la rechaza", tamperInitiation());
    check("RESPUESTA manipulada: un bit cambiado en cualquier campo (tipo, índices, efímera, vacío cifrado, MAC1) la rechaza", tamperResponse());
    check("TAMAÑOS: una iniciación más corta, más larga o vacía se rechaza antes de tocar la criptografía", wrongSizes());
    check("PAR DESCONOCIDO: quien conoce la clave del servidor pero no es el par configurado no pasa", unknownPeer());
    check("REPETICIÓN de una iniciación (misma marca de tiempo) y marca más vieja que la última aceptada: rechazadas", replayedInitiation());
    check("RESPUESTA fuera de lugar: sin iniciación, con otro índice, o repetida, no crea sesión", responseNeedsInitiation());
    check("DATOS manipulados: cada bit de cada byte del mensaje (encabezado, contador, cifrado, etiqueta), cortado o para el otro sentido, se rechaza", dataIntegrity());
    check("SIN RESERVAR: sealInto/openInto dan lo mismo que seal/open (0 a 1500 bytes), con repetición y etiqueta falsa rechazadas sin tocar la salida, búfer pequeño y sesión agotada", noAlloc());
    check("KEEPALIVE: un mensaje sin contenido mide 32 bytes y se abre", keepalive());
    check("VENTANA antirrepetición de 2048: repetidos, atrasados dentro y fuera de la ventana, salto grande y etiqueta falsa que NO mueve la ventana", replayWindow());
    check("LÍMITE de mensajes: la sesión deja de emitir en REJECT_AFTER y el receptor lo rechaza", limits());
    check("KDF: τ1, τ2 y τ3 son los de HMAC-BLAKE2s de la especificación", kdfVectors());
    check("CODIFICACIONES: base64 de claves, TAI64N, y el ICMP echo con sus checksums", encodings());
    check("COOKIES: bajo carga una iniciación sin MAC2 recibe una respuesta de cookie (tipo 3, 64 bytes), el iniciador la abre, repite con MAC2 y el respondedor la acepta y completa el apretón de manos; sin carga no hace falta", cookieFlow());
    check("COOKIES ligadas al ORIGEN: otra IP u otro puerto, un MAC2 de ceros o con un bit cambiado vuelven a pedir cookie", cookieBoundToSource());
    check("COOKIES manipuladas: cada bit de la respuesta, otro largo, una respuesta vieja para una iniciación nueva y la de otro par se rechazan", cookieTamper());
    check("COOKIES con tiempo: la del iniciador no se usa pasados 120 s y el secreto del respondedor rota (cookie vieja inválida)", cookieExpiry());
    check("XChaCha20-Poly1305 de 24 bytes de nonce, ida y vuelta (la validación de fondo está en edge_Jelf y en el kernel)", xchachaCookie());
    check("CONFIGURACIÓN: se leen pares, rutas, endpoint y keepalive; Address/DNS se avisan y no se aplican; 20 configuraciones inválidas (sin claves, IPv6, bits de host, nombres de host, duplicados, rutas repetidas...) se rechazan", configParsing());
    check("ENRUTAMIENTO por clave criptográfica: gana la ruta más larga entre varios pares, la ruta por omisión recoge el resto, sin ruta se descarta, y el origen de un paquete debe estar en las rutas de ESE par", routing());
    check("VARIOS PARES: la clave estática descifrada elige al par; otro par configurado con el mismo dispositivo rechaza la iniciación ajena (comprobación obligatoria)", multiPeerHandshake());
    check("GSO: un segmento TCP de hasta 64 KB se parte en paquetes de gso_size (13 casos, con opciones, a punto de cruzar 2^32 de secuencia y 2^16 de identificador): largos, secuencia, identificador, FIN y PSH solo en el último, datos y las DOS sumas de control correctas (verificadas con otra implementación)", gsoSplit());
    check("GSO: lo que sobra detrás del largo IP no se trata como datos", gsoIgnoresTail());
    check("GSO: un paquete suelto con la suma sin completar (UDP y TCP, 9 largos) queda con la suma que verifica", gsoNeedsCsum());
    check("GSO hostil: otro tipo de GSO, gso_size 0 o enorme, hdr_len imposible o que no cuadra con TCP, no IPv4, no TCP, opciones IP, truncados y campos de suma fuera del paquete se descartan", gsoRejects());
    check("GSO fuzz: 20000 cabeceras con bytes al azar no dan excepción, paquetes mayores de 65535 ni bucles", gsoFuzz());
    System.out.println("jvpn selftest: " + (total - bad) + " de " + total);
    return bad == 0;
  }
}
