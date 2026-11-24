/*
 * Copyright © 2018-2026 Diego Fernando Mayor Rojas. Todos los derechos reservados.
 *
 * Este archivo es parte de jelf. Software propietario:
 * queda prohibida su copia, uso, modificación o distribución
 * sin autorización expresa y por escrito del autor. Ver el archivo LICENSE.
 */
/*
 * Handshake.java - El apretón de manos de WireGuard (Noise_IKpsk2) en sus dos papeles, para UN par configurado: clave privada propia, clave pública del par y clave precompartida opcional (32 ceros si no hay).
 * Iniciador: createInitiation() y consumeResponse(). Respondedor: consumeInitiation() y createResponse(). Todo mensaje que llega es hostil: se comprueba MAC1 antes de gastar una multiplicación de curva,
 * el par debe ser el configurado, la marca de tiempo debe ser MAYOR que la última aceptada (contra repetición de iniciaciones) y cualquier fallo devuelve null sin cambiar el estado visible.
 * Sin cookies todavía (MAC2 va en ceros y los mensajes tipo 3 se ignoran): bajo carga el kernel pediría una cookie; ver AUDITORIA.md.
 */

public final class Handshake {
  final byte[] sPriv;
  public final byte[] sPub;
  final byte[] peerPub;
  final byte[] psk;
  final byte[] myMac1Key;
  final byte[] peerMac1Key;
  /** Lado respondedor de las cookies (secreto por origen). */
  public final Cookies cookies = new Cookies();
  /** Lado iniciador: la última cookie recibida del par, su momento, y el MAC1 de la última iniciación (es el dato asociado de la respuesta de cookie). */
  byte[] cookie;
  long cookieTime;
  byte[] lastMac1;
  /** La respuesta de cookie preparada por consume() cuando devuelve COOKIE. */
  public byte[] cookieReply;
  public static final int REJECT = 0;
  public static final int ACCEPT = 1;
  public static final int COOKIE = 2;

  /** Última marca de tiempo aceptada del par (12 ceros al principio). */
  byte[] lastTimestamp = new byte[12];
  public long nowMillis; // para las pruebas: 0 = el reloj real

  // estado del iniciador en vuelo
  byte[] ePriv;
  byte[] c;
  byte[] h;
  int localIndex;
  boolean waiting;

  // estado del respondedor entre consumeInitiation y createResponse
  byte[] rc;
  byte[] rh;
  byte[] ePubI;
  int remoteIndex;

  public Handshake(byte[] sPriv, byte[] peerPub, byte[] psk) {
    this.sPriv = sPriv;
    this.sPub = X25519.publicKey(sPriv);
    this.peerPub = peerPub;
    this.psk = psk == null ? new byte[32] : psk;
    this.myMac1Key = Wg.mac1Key(sPub);
    this.peerMac1Key = Wg.mac1Key(peerPub);
  }

  static byte[] newPriv() {
    return Wg.clamp(Rand.bytes(32));
  }

  long now() {
    return nowMillis != 0 ? nowMillis : System.currentTimeMillis();
  }

  // ------------------------------------------------------------------ iniciador

  public byte[] createInitiation() {
    byte[] cc = Wg.hash(Wg.CONSTRUCTION, null);
    byte[] hh = Wg.hash(cc, Wg.IDENTIFIER);
    hh = Wg.hash(hh, peerPub);
    byte[] ep = newPriv();
    byte[] epub = X25519.publicKey(ep);
    cc = Wg.kdf(cc, epub, 1)[0];
    hh = Wg.hash(hh, epub);
    byte[] dh = X25519.shared(ep, peerPub);
    if (dh == null) return null;
    byte[][] k = Wg.kdf(cc, dh, 2);
    cc = k[0];
    byte[] stat = Wg.seal(k[1], 0, hh, sPub);
    hh = Wg.hash(hh, stat);
    dh = X25519.shared(sPriv, peerPub);
    if (dh == null) return null;
    k = Wg.kdf(cc, dh, 2);
    cc = k[0];
    byte[] ts = Wg.seal(k[1], 0, hh, Wg.tai64n(now()));
    hh = Wg.hash(hh, ts);
    int idx = Wg.getLE32(Rand.bytes(4), 0);
    byte[] m = new byte[Wg.INITIATION];
    m[0] = 1;
    Wg.putLE32(m, 4, idx);
    Wg.copy(epub, 0, m, 8, 32);
    Wg.copy(stat, 0, m, 40, 48);
    Wg.copy(ts, 0, m, 88, 28);
    byte[] mac1 = Wg.mac(peerMac1Key, m, 116);
    Wg.copy(mac1, 0, m, 116, 16);
    lastMac1 = mac1;
    if (cookie != null && now() - cookieTime < Cookies.SECRET_LIFE_MS) { // con una cookie vigente del par, el MAC2 la prueba (bajo carga el par lo exige)
      byte[] mac2 = Wg.mac(cookie, m, 132);
      Wg.copy(mac2, 0, m, 132, 16);
    }
    this.ePriv = ep;
    this.c = cc;
    this.h = hh;
    this.localIndex = idx;
    this.waiting = true;
    return m;
  }

  /** Procesa la respuesta (tipo 2); devuelve la sesión, o null si no vale. */
  public Session consumeResponse(byte[] m, int len) {
    if (!waiting || len != Wg.RESPONSE || m[0] != 2 || m[1] != 0 || m[2] != 0 || m[3] != 0) return null;
    byte[] mac1 = Wg.mac(myMac1Key, m, 60);
    if (!Wg.same(mac1, 0, m, 60, 16)) return null;
    if (Wg.getLE32(m, 8) != localIndex) return null;
    int remote = Wg.getLE32(m, 4);
    byte[] epubR = new byte[32];
    Wg.copy(m, 12, epubR, 0, 32);
    byte[] cc = Wg.kdf(c, epubR, 1)[0];
    byte[] hh = Wg.hash(h, epubR);
    byte[] dh = X25519.shared(ePriv, epubR);
    if (dh == null) return null;
    cc = Wg.kdf(cc, dh, 1)[0];
    dh = X25519.shared(sPriv, epubR);
    if (dh == null) return null;
    cc = Wg.kdf(cc, dh, 1)[0];
    byte[][] k = Wg.kdf(cc, psk, 3);
    cc = k[0];
    hh = Wg.hash(hh, k[1]);
    byte[] empty = Wg.open(k[2], 0, hh, m, 44, 16);
    if (empty == null) return null;
    byte[] ct = new byte[16];
    Wg.copy(m, 44, ct, 0, 16);
    hh = Wg.hash(hh, ct);
    byte[][] t = Wg.kdf(cc, new byte[0], 2);
    waiting = false;
    return new Session(t[0], t[1], localIndex, remote, true);
  }

  /** Procesa una respuesta de cookie (tipo 3): si es para nuestra última iniciación y abre con la clave del par, guarda la cookie y devuelve true. */
  public boolean consumeCookieReply(byte[] m, int len) {
    if (!waiting || lastMac1 == null || len != Cookies.REPLY || m[0] != 3 || m[1] != 0 || m[2] != 0 || m[3] != 0) return false;
    if (Wg.getLE32(m, 4) != localIndex) return false;
    byte[] nonce = new byte[24];
    Wg.copy(m, 8, nonce, 0, 24);
    byte[] c = XChaCha20Poly1305.open(Wg.cookieKey(peerPub), nonce, lastMac1, m, 32, 32);
    if (c == null || c.length != 16) return false;
    cookie = c;
    cookieTime = now();
    return true;
  }

  // ------------------------------------------------------------------ respondedor

  /** ¿Es una iniciación del largo y tipo justos con MAC1 válido? Barato (un BLAKE2s): sirve para contar y limitar antes de gastar curvas elípticas. */
  public boolean mac1Ok(byte[] m, int len) {
    if (len != Wg.INITIATION || m[0] != 1 || m[1] != 0 || m[2] != 0 || m[3] != 0) return false;
    return Wg.same(Wg.mac(myMac1Key, m, 116), 0, m, 116, 16);
  }

  /**
   * Como consumeInitiation pero con cookies: bajo carga una iniciación SIN un MAC2 válido para su origen (ip, puerto) no se procesa; devuelve COOKIE y deja la respuesta en cookieReply.
   * Devuelve REJECT si no vale y ACCEPT si se procesó (y sigue createResponse).
   */
  public int consume(byte[] m, int len, int ip, int port, boolean underLoad) {
    if (!mac1Ok(m, len)) return REJECT;
    if (underLoad && !cookies.mac2Valid(m, 132, ip, port, now())) {
      cookieReply = cookies.reply(m, 116, ip, port, sPub, now());
      return COOKIE;
    }
    return consumeInitiation(m, len) ? ACCEPT : REJECT;
  }

  /** Procesa una iniciación (tipo 1); true si es del par configurado, con MAC1 y marca de tiempo válidas. Deja el estado para createResponse. */
  public boolean consumeInitiation(byte[] m, int len) {
    if (len != Wg.INITIATION || m[0] != 1 || m[1] != 0 || m[2] != 0 || m[3] != 0) return false;
    byte[] mac1 = Wg.mac(myMac1Key, m, 116);
    if (!Wg.same(mac1, 0, m, 116, 16)) return false;
    byte[] cc = Wg.hash(Wg.CONSTRUCTION, null);
    byte[] hh = Wg.hash(cc, Wg.IDENTIFIER);
    hh = Wg.hash(hh, sPub);
    byte[] epub = new byte[32];
    Wg.copy(m, 8, epub, 0, 32);
    cc = Wg.kdf(cc, epub, 1)[0];
    hh = Wg.hash(hh, epub);
    byte[] dh = X25519.shared(sPriv, epub);
    if (dh == null) return false;
    byte[][] k = Wg.kdf(cc, dh, 2);
    cc = k[0];
    byte[] stat = Wg.open(k[1], 0, hh, m, 40, 48);
    if (stat == null || !Wg.same(stat, 0, peerPub, 0, 32)) return false;
    byte[] statCt = new byte[48];
    Wg.copy(m, 40, statCt, 0, 48);
    hh = Wg.hash(hh, statCt);
    dh = X25519.shared(sPriv, peerPub);
    if (dh == null) return false;
    k = Wg.kdf(cc, dh, 2);
    cc = k[0];
    byte[] ts = Wg.open(k[1], 0, hh, m, 88, 28);
    if (ts == null || !Wg.newer(ts, lastTimestamp)) return false;
    byte[] tsCt = new byte[28];
    Wg.copy(m, 88, tsCt, 0, 28);
    hh = Wg.hash(hh, tsCt);
    lastTimestamp = ts;
    rc = cc;
    rh = hh;
    ePubI = epub;
    remoteIndex = Wg.getLE32(m, 4);
    return true;
  }

  /** Arma la respuesta; devuelve {mensaje, null} y deja la sesión en session(). Llamar solo tras un consumeInitiation verdadero. */
  public byte[] createResponse() {
    byte[] ep = newPriv();
    byte[] epub = X25519.publicKey(ep);
    byte[] cc = Wg.kdf(rc, epub, 1)[0];
    byte[] hh = Wg.hash(rh, epub);
    byte[] dh = X25519.shared(ep, ePubI);
    if (dh == null) return null;
    cc = Wg.kdf(cc, dh, 1)[0];
    dh = X25519.shared(ep, peerPub);
    if (dh == null) return null;
    cc = Wg.kdf(cc, dh, 1)[0];
    byte[][] k = Wg.kdf(cc, psk, 3);
    cc = k[0];
    hh = Wg.hash(hh, k[1]);
    byte[] empty = Wg.seal(k[2], 0, hh, new byte[0]);
    int idx = Wg.getLE32(Rand.bytes(4), 0);
    byte[] m = new byte[Wg.RESPONSE];
    m[0] = 2;
    Wg.putLE32(m, 4, idx);
    Wg.putLE32(m, 8, remoteIndex);
    Wg.copy(epub, 0, m, 12, 32);
    Wg.copy(empty, 0, m, 44, 16);
    byte[] mac1 = Wg.mac(peerMac1Key, m, 60);
    Wg.copy(mac1, 0, m, 60, 16);
    byte[][] t = Wg.kdf(cc, new byte[0], 2);
    pending = new Session(t[1], t[0], idx, remoteIndex, false);
    rc = null;
    return m;
  }

  /** La sesión que dejó el último createResponse (null si no hay). */
  public Session pending;
}
