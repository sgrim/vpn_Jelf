# Auditoría — vpn_Jelf

## 1. Origen y decisiones de partida (2026-11-26)

**Origen.** Idea del autor: un proyecto VPN con línea de órdenes. Repositorio: https://github.com/sgrim/vpn_Jelf.git. Se creó junto con `ssh_Jelf`.
**Decisión 1: compatible con WireGuard, no un protocolo propio.** Inventar un protocolo o criptografía propios sería el mayor riesgo posible. WireGuard es pequeño, estándar de hecho y revisado; el kernel de esta máquina lo trae (`CONFIG_WIREGUARD=y`), así que **la interoperabilidad en los dos sentidos con el kernel es la prueba principal**.
**Decisión 2: la integración con la nube, no «más rápido que el kernel».** El kernel de WireGuard llegará a varios Gbit/s; un proceso de usuario en jelf no. El valor es la red privada entre las microVM de un cliente con el plano de control; la velocidad se medirá y se declarará tal cual.
**Decisión 3: los riesgos se anotan antes de escribir código y se validan por fases** (`RIESGOS.md`: 19 propios y 3 transversales). Regla de la puerta: no se usa con tráfico de clientes mientras haya un riesgo grave abierto.
**Estado:** esqueleto; ningún riesgo está validado todavía.
