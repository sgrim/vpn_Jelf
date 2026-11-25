/*
 * Copyright © 2018-2026 Diego Fernando Mayor Rojas. Todos los derechos reservados.
 *
 * Este archivo es parte de jelf. Software propietario:
 * queda prohibida su copia, uso, modificación o distribución
 * sin autorización expresa y por escrito del autor. Ver el archivo LICENSE.
 */
/*
 * InitLimiter.java - Control de admisión de los mensajes de iniciación del apretón de manos (cada uno cuesta varias multiplicaciones de curva). TRES presupuestos distintos, para que ningún atacante agote el de otro:
 *   (1) LLEGADAS (arrive): cuántas iniciaciones con MAC1 válido llegan por segundo. Es barato (un contador); pasado el umbral el dispositivo está «bajo carga» y exige MAC2 (una cookie que demuestra que quien escribe
 *       es dueño de su IP: una IP falsificada nunca la tiene). Las llegadas sin MAC2 NO gastan ni el presupuesto por origen ni el global: un atacante que falsifica orígenes no deja fuera a nadie.
 *   (2) POR ORIGEN (admit): un cubo de fichas por IP de origen (ya probada con MAC2 si hay carga): ráfaga de BURST y reposición de REFILL_PER_SEC por segundo. Una sola IP que inunda se queda sin fichas y no toca el
 *       presupuesto de las demás. La tabla es de tamaño fijo (SLOTS) con una IP por casilla: otra IP con la misma casilla la reemplaza (el que reemplaza empieza con el cubo lleno; un atacante con MUCHAS IPs reales
 *       sí puede eludir este límite, y para eso está el tercero).
 *   (3) GLOBAL (admit): tope de iniciaciones CARAS por segundo (las que pasaron el control por origen), el último recurso contra muchas IPs reales.
 * Sin reservas por llamada ni recursión. Probado en VpnTest sin red ni reloj real (el tiempo lo da quien llama).
 */

public final class InitLimiter {
  public static final int GLOBAL_PER_SEC = 20;
  public static final int LOAD_ARRIVALS = GLOBAL_PER_SEC / 4;
  public static final int BURST = 5;
  public static final int REFILL_PER_SEC = 2;
  public static final int SLOTS = 256;
  static final int COST = 1000; // una ficha = 1000 unidades; la reposición es REFILL_PER_SEC unidades por milisegundo

  static final int OK = 0;
  static final int DROP_SOURCE = 1;
  static final int DROP_GLOBAL = 2;

  final int[] slotIp = new int[SLOTS];
  final boolean[] slotUsed = new boolean[SLOTS];
  final long[] slotTime = new long[SLOTS];
  final int[] slotTokens = new int[SLOTS];
  long windowStart;
  int arrivals;
  int expensive;
  /** El motivo del último rechazo de admit (OK si se admitió). */
  public int lastReason;

  void roll(long now) {
    if (now - windowStart >= 1000 || now < windowStart) { // el reloj puede ir hacia atrás
      windowStart = now;
      arrivals = 0;
      expensive = 0;
    }
  }

  /** Una iniciación con MAC1 válido llega. Devuelve true si el dispositivo está bajo carga (hay que exigir MAC2). */
  public boolean arrive(long now) {
    roll(now);
    arrivals++;
    return arrivals > LOAD_ARRIVALS;
  }

  static int slotOf(int ip) {
    int h = ip * 0x9E3779B1;
    return (h >>> 24) & (SLOTS - 1);
  }

  /** ¿Se admite la iniciación (ya con MAC2 válido si hay carga) de esa IP? Gasta una ficha del origen y una del tope global. */
  public boolean admit(int srcIp, long now) {
    roll(now);
    int s = slotOf(srcIp);
    if (!slotUsed[s] || slotIp[s] != srcIp) { // casilla vacía o de otra IP: empieza con el cubo lleno
      slotUsed[s] = true;
      slotIp[s] = srcIp;
      slotTime[s] = now;
      slotTokens[s] = BURST * COST;
    } else {
      long el = now - slotTime[s];
      if (el < 0) el = 0; // reloj hacia atrás: sin reposición
      if (el > 10000) el = 10000; // 10 s bastan para llenar el cubo; así el producto no desborda con un reloj extremo
      long t = slotTokens[s] + el * REFILL_PER_SEC;
      slotTokens[s] = t > BURST * COST ? BURST * COST : (int) t;
      slotTime[s] = now;
    }
    if (slotTokens[s] < COST) {
      lastReason = DROP_SOURCE;
      return false;
    }
    if (expensive >= GLOBAL_PER_SEC) {
      lastReason = DROP_GLOBAL;
      return false;
    }
    slotTokens[s] -= COST;
    expensive++;
    lastReason = OK;
    return true;
  }
}
