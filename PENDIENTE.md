# Pendiente — vpn_Jelf

Tamaños relativos: S < M < L < XL. Los riesgos de cada fase y su validación están en `RIESGOS.md` (una fase no se da por terminada si deja un riesgo de gravedad alta sin su prueba).

## 0. Requisitos en `edge_Jelf` (M) — HECHO el 2026-11-26 salvo XChaCha20 (edge_Jelf AUDITORIA 4)
- **X25519**, **ChaCha20-Poly1305**, **HKDF** y **BLAKE2s** (más el `XChaCha20-Poly1305` de las cookies), con los vectores oficiales y con la JVM 26 y OpenSSL como comparadores.

## 1. V0 — el protocolo (L): HECHO el núcleo (AUDITORIA.md 2); cookies y MAC2 HECHOS (AUDITORIA.md 4); faltan límite por origen, varios pares
- Apretón de manos Noise_IKpsk2 (iniciador y respondedor), mensajes de datos con contador y ventana antirrepetición de 2000, marcas TAI64N, cookies y `MAC1`/`MAC2`, temporizadores (renovación, rechazo, keepalive).
- **Salida:** apretón de manos y paquetes de datos en los dos sentidos con el **WireGuard del kernel** (espacio de nombres de red).

## 2. V1 — la herramienta en modo usuario (L): HECHO el núcleo (AUDITORIA.md 3); faltan varios pares, archivo de configuración con permisos 0600, `show`/`set`, IPv6, cookies
- `jvpn genkey`, `pubkey`, `up CONFIG`, `show`, `set`; interfaz TUN, socket UDP, soltar privilegios antes del primer paquete, archivo de configuración con permisos 0600.

## 3. V2 — rutas, DNS y tamaños (M): HECHOS varios pares, archivo de configuración y enrutamiento por clave (AUDITORIA.md 5); falta lo que sigue
- Política de rutas IPv4 e IPv6, DNS por el túnel, interruptor si el túnel cae, MTU 1420.

## 4. V3 — rendimiento (L)
- ChaCha20-Poly1305 con SIMD y por lotes, lectura y escritura de varios paquetes, un `Worker` por grupo de pares; banco contra el kernel, `wireguard-go` y BoringTun (Gbit/s, CPU por Gbit, latencia, memoria).

## 5. V4 — endurecimiento (M)
- Fuzz de mensajes, tiempos y secretos en memoria, registros sin tráfico, opción de clave precompartida poscuántica con un diseño publicado (no inventado), **revisión externa**.

## 6. V5 — integración con la nube (L)
- Una interfaz por inquilino, claves públicas repartidas por el plano de control, revocación inmediata, aislamiento entre inquilinos probado, decisión escrita de dónde corre (microVM del cliente por omisión).
