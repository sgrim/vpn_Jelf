#!/bin/sh
# Túnel COMPLETO con «interruptor de seguridad» (R-V05), con las herramientas del sistema (ip): todo el tráfico sin marca sale por la interfaz del túnel; el de jvpn mismo (UDP marcado con FwMark) sale por la tabla normal.
# Uso:  fullroute.sh up|down INTERFAZ MARCA [TABLA]      (necesita privilegios; la interfaz ya debe existir y estar arriba, p. ej. creada por «jvpn up --persist»)
# El interruptor es la INTERFAZ PERSISTENTE (jvpn up --persist): si jvpn muere, la interfaz y estas rutas siguen y el tráfico va a un dispositivo sin lector y se pierde, no sale en claro por otra ruta.
# IPv6 NO está soportado por jvpn: la ruta por omisión IPv6 se vuelve «inalcanzable» (métrica 1) para que no salga fuera del túnel (se probó que algunos núcleos, como el de WSL2, no tienen reglas de rutas IPv6). DNS: apunte /etc/resolv.conf a un servidor al que se llegue POR el túnel (este script no lo toca).
set -e
cmd="$1"; dev="$2"; mark="$3"; table="${4:-51820}"
[ -n "$cmd" ] && [ -n "$dev" ] && [ -n "$mark" ] || { echo "uso: $0 up|down INTERFAZ MARCA [TABLA]"; exit 2; }
case "$cmd" in
  up)
    ip route replace default dev "$dev" table "$table"
    ip rule add not fwmark "$mark" table "$table" pref 100
    ip rule add table main suppress_prefixlength 0 pref 99   # rutas locales más específicas que la omisión (la red local, el túnel mismo) siguen en la tabla principal
    ip -6 route replace unreachable default metric 1 2>/dev/null || true   # sin depender de reglas IPv6 (algunos núcleos no las tienen): la ruta por omisión IPv6 de menor métrica es «inalcanzable»; las redes locales (más específicas) siguen directas
    ;;
  down)
    ip rule del table main suppress_prefixlength 0 pref 99 2>/dev/null || true
    ip rule del not fwmark "$mark" table "$table" pref 100 2>/dev/null || true
    ip route flush table "$table" 2>/dev/null || true
    ip -6 route del unreachable default metric 1 2>/dev/null || true
    ;;
  *) echo "uso: $0 up|down INTERFAZ MARCA [TABLA]"; exit 2 ;;
esac
