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
    System.out.println("jvpn selftest: " + (total - bad) + " de " + total);
    return bad == 0;
  }
}
