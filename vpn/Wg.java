/*
 * Copyright © 2018-2026 Diego Fernando Mayor Rojas. Todos los derechos reservados.
 *
 * Este archivo es parte de jelf. Software propietario:
 * queda prohibida su copia, uso, modificación o distribución
 * sin autorización expresa y por escrito del autor. Ver el archivo LICENSE.
 */
/*
 * Wg.java - Primitivas del protocolo WireGuard (whitepaper de Jason Donenfeld, «Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s»): HASH, KDF, AEAD con contador, MAC de BLAKE2s con clave, TAI64N y utilidades de bytes.
 * Solo se usan las piezas de edge_Jelf (BLAKE2s, ChaCha20-Poly1305, X25519), sin variantes propias. Nada aquí guarda estado.
 */

public final class Wg {
  public static final byte[] CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".getBytes();
  public static final byte[] IDENTIFIER = "WireGuard v1 zx2c4 Jason@zx2c4.com".getBytes();
  public static final byte[] LABEL_MAC1 = "mac1----".getBytes();
  public static final int INITIATION = 148;
  public static final int RESPONSE = 92;
  public static final int DATA_HEADER = 16;
  public static final int TAG = 16;

  public static byte[] hash(byte[] a, byte[] b) {
    Blake2s h = new Blake2s(32);
    h.update(a, 0, a.length);
    if (b != null) h.update(b, 0, b.length);
    return h.digest();
  }

  /** τ0 = HMAC(key, input); devuelve τ(1), τ(2) o τ(3) según n (1..3) en un arreglo de n elementos. */
  public static byte[][] kdf(byte[] key, byte[] input, int n) {
    byte[] t0 = Blake2s.hmac(key, input);
    byte[][] out = new byte[n][];
    byte[] prev = new byte[0];
    for (int i = 0; i < n; i++) {
      byte[] m = new byte[prev.length + 1];
      for (int j = 0; j < prev.length; j++) m[j] = prev[j];
      m[prev.length] = (byte) (i + 1);
      prev = Blake2s.hmac(t0, m);
      out[i] = prev;
    }
    return out;
  }

  /** El nonce de 12 bytes: 32 bits en cero y el contador de 64 bits, little-endian. */
  public static byte[] nonce(long counter) {
    byte[] n = new byte[12];
    for (int i = 0; i < 8; i++) n[4 + i] = (byte) (counter >>> (8 * i));
    return n;
  }

  public static byte[] seal(byte[] key, long counter, byte[] aad, byte[] pt) {
    return ChaCha20Poly1305.seal(key, nonce(counter), aad, pt, 0, pt.length);
  }

  public static byte[] open(byte[] key, long counter, byte[] aad, byte[] ct, int off, int len) {
    return ChaCha20Poly1305.open(key, nonce(counter), aad, ct, off, len);
  }

  /** MAC1/MAC2: BLAKE2s de 16 bytes con clave de 32 sobre msg[0..len). */
  public static byte[] mac(byte[] key, byte[] msg, int len) {
    return new Blake2s(16, key).update(msg, 0, len).digest();
  }

  /** La clave de MAC1 de quien RECIBE: HASH("mac1----" ‖ su clave pública). */
  public static byte[] mac1Key(byte[] receiverPub) {
    return hash(LABEL_MAC1, receiverPub);
  }

  /** Comparación en tiempo constante. */
  public static boolean same(byte[] a, int ao, byte[] b, int bo, int n) {
    int d = 0;
    for (int i = 0; i < n; i++) d |= a[ao + i] ^ b[bo + i];
    return d == 0;
  }

  public static byte[] concat(byte[] a, byte[] b) {
    byte[] r = new byte[a.length + b.length];
    for (int i = 0; i < a.length; i++) r[i] = a[i];
    for (int i = 0; i < b.length; i++) r[a.length + i] = b[i];
    return r;
  }

  public static void copy(byte[] src, int so, byte[] dst, int d, int n) {
    for (int i = 0; i < n; i++) dst[d + i] = src[so + i];
  }

  public static void putLE32(byte[] b, int off, int v) {
    for (int i = 0; i < 4; i++) b[off + i] = (byte) (v >>> (8 * i));
  }

  public static int getLE32(byte[] b, int off) {
    return (b[off] & 255) | ((b[off + 1] & 255) << 8) | ((b[off + 2] & 255) << 16) | ((b[off + 3] & 255) << 24);
  }

  public static void putLE64(byte[] b, int off, long v) {
    for (int i = 0; i < 8; i++) b[off + i] = (byte) (v >>> (8 * i));
  }

  public static long getLE64(byte[] b, int off) {
    long v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | (b[off + i] & 255);
    return v;
  }

  /** TAI64N de 12 bytes: segundos + 2^62 + 10 en big-endian y nanosegundos. */
  public static byte[] tai64n(long millis) {
    long secs = millis / 1000 + 4611686018427387914L;
    long nanos = (millis % 1000) * 1000000L;
    byte[] t = new byte[12];
    for (int i = 0; i < 8; i++) t[i] = (byte) (secs >>> (56 - 8 * i));
    for (int i = 0; i < 4; i++) t[8 + i] = (byte) (nanos >>> (24 - 8 * i));
    return t;
  }

  /** ¿a es estrictamente mayor que b (12 bytes, big-endian)? */
  public static boolean newer(byte[] a, byte[] b) {
    for (int i = 0; i < 12; i++) {
      int x = a[i] & 255;
      int y = b[i] & 255;
      if (x != y) return x > y;
    }
    return false;
  }

  public static byte[] clamp(byte[] k) {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    return k;
  }
}
