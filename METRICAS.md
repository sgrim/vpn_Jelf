# Métricas de jvpn (medidas, no estimadas) — 2026-11-26

**Entorno de todas las cifras:** AMD Ryzen 7 4700U (8 núcleos), 5 GB de RAM, WSL2 anidado (núcleo 5.10.102.1-microsoft-standard-WSL2), docker con dos o tres contenedores en la MISMA máquina unidos por veth; JVM 21.0.11 y gcc 14.2.0 solo para las herramientas. El receptor del par corre en la misma CPU que el emisor (la veth ejecuta su trabajo en la CPU de quien envía), así que NO son cifras de dos máquinas ni de una NIC real, y no se midió ARM ni RISC-V reales. El ruido entre ejecuciones del banco es de ±10 % (a veces ±30 %): una diferencia menor que eso no es una diferencia. Reproducir: `tools/bench_tunnel.sh [segundos]` (iperf3 TCP) y `build/jvpn bench` (en memoria).

## Resumen: el kernel es más rápido

| | Mbit/s (iperf3 TCP, 1 flujo, MTU 1420) | Frente al kernel |
|---|---|---|
| WireGuard del **kernel** ↔ kernel | 766–820 | 100 % |
| **jvpn** → kernel (subida) | 285–313 | ≈ 37–39 % |
| **jvpn** ← kernel (bajada) | 282–301 | ≈ 36–38 % |
| jvpn → kernel, 4 flujos (suma) | 290–312 (cada flujo ≈ 55–97) | ≈ 38 % |

**Con jvpn el túnel rinde un poco más de un tercio de lo que da el kernel.** Es un límite de un solo hilo: jvpn usa un núcleo al 100 %; el kernel reparte el cifrado entre núcleos y usa ChaCha20 con instrucciones vectoriales.

## Cifrado en memoria (un núcleo, sin red, paquetes de 1 400 bytes)

| Operación | Paquetes/s | Mbit/s |
|---|---|---|
| Cifrar (`sealInto`, búfer fijo) | 83 700 | 937 |
| Abrir (`openInto`, con ventana antirrepetición) | 92 592 | 1 037 |
| Apretones de manos completos (los dos lados) | 311 por segundo | — |

Evolución del cifrado: 547 (inicio) → 675 (`Sys.rotl32`) → 962 Mbit/s (búferes fijos, sin copias de más); abrir: 676 → 861 → 1 037.

## Coste de CPU del túnel real (5 mediciones de 6 s, jvpn al 100 % de un núcleo)

- Modo usuario ≈ 30–40 % (cifrado, copias, recolector) y modo núcleo ≈ 60–70 % (`sendmmsg`/`recvmmsg`, lecturas y escrituras de la TUN y el trabajo del receptor en la misma CPU).
- En ticks de CPU por megabit movido: ≈ 0,31 (sin GSO) y ≈ 0,33 (con `--gso`).
- Memoria residente ≈ 18 MB; binario ≈ 161 KB; sin dependencias.

## Historia de las mejoras (cada una con su medida)

| Paso | Mbit/s por túnel | `AUDITORIA.md` |
|---|---|---|
| Primera versión medida | ≈ 210–235 | 7 |
| + rotaciones de una instrucción | ≈ 230 | 7 |
| + búferes fijos y `sendmmsg`/`recvmmsg` | ≈ 285 (−21 % de memoria) | 8 |
| + GSO en la TUN (`--gso`) | ≈ 285–300: **sin ganancia** | 12 |

## Por qué importa que sea más lento, y qué falta (PENDIENTE.md, V3)

1. **Entender el modo núcleo (≈ 28 µs por paquete frente a ≈ 14 µs de TODO en el kernel):** es donde está el hueco. ChaCha20 SIMD ahorraría ≈ 5 µs de ≈ 38 (≈ +13 %): `AUDITORIA.md` 13. Falta contar las llamadas al sistema por paquete y quién ejecuta el trabajo del receptor.
2. **Varios trabajadores** por par: exige repartir el contador de mensajes y la ventana antirrepetición de UN par entre procesos sin memoria compartida; es un rediseño, no un ajuste.
3. **Un perfilador:** en esta máquina no hay `perf` ni `strace`; sin él no se separa lo que cuesta el receptor de lo que cuesta jvpn.
4. **Medir en dos máquinas reales** (con una NIC de verdad) para quitar el efecto de que el receptor corra en la misma CPU.
5. Comparar con `wireguard-go` y BoringTun (no están instalados: no se afirma nada contra ellos).

## Dónde se va el tiempo de un paquete (1 408 bytes, un núcleo; `AUDITORIA.md` 13)

| Parte | µs por paquete |
|---|---|
| ChaCha20 (cifrar) | ≈ 6,6 |
| Poly1305 (etiqueta) | ≈ 3,1 |
| `sealInto` completo | ≈ 9,8 |
| Total de CPU de jvpn a ≈ 300 Mbit/s | ≈ 38 |
| Resto (modo núcleo, receptor en la misma CPU, recolector) | ≈ 28 |
| Kernel ↔ kernel a ≈ 800 Mbit/s, TODO | ≈ 14 |
