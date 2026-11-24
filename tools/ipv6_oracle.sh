#!/bin/sh
# R-V05, IPv6: jvpn no maneja IPv6, así que con el túnel completo el IPv6 no debe salir por la ruta normal (sería una fuga en claro). tools/fullroute.sh lo bloquea con una ruta «unreachable» en la tabla del túnel.
# Un contenedor (con CAP_SYS_ADMIN) y dos espacios de red unidos por una veth: B (el contenedor) con la puerta de enlace IPv6 en T (un espacio de red) que tiene la dirección «de Internet» fd00:9::9.
# (Las redes IPv6 de docker no funcionan en este entorno: faltan cadenas de ip6tables.) Se prueba (1) que SIN fullroute el ping IPv6 llega a T (línea base: la prueba ve el tráfico), (2) CON fullroute el ping falla de
# inmediato y a T no le llega ni un eco, (3) tras «down» vuelve a llegar. No hace falta jvpn: se prueba el script de rutas. Necesita docker; si no, se omite.
cd "$(dirname "$0")/.."
command -v docker > /dev/null 2>&1 || { echo "omitido  sin docker no se prueba el IPv6"; exit 0; }
docker image inspect jvpn-wgkernel:test > /dev/null 2>&1 || docker build -q -t jvpn-wgkernel:test tools/wgkernel > /dev/null || { echo "FALLA  no se pudo construir la imagen del comparador"; exit 1; }
bad=0
ok() { echo "ok     $1"; }
fail() { echo "FALLA  $1"; bad=1; }
B=jvpn_v6_$$
cleanup() { docker rm -f $B > /dev/null 2>&1; }
trap cleanup EXIT
docker run -d --rm --name $B --cap-add NET_ADMIN --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined --device /dev/net/tun jvpn-wgkernel:test > /dev/null || { echo "omitido  no arranca el contenedor con CAP_SYS_ADMIN"; exit 0; }
docker cp tools/fullroute.sh $B:/fullroute.sh > /dev/null
docker exec $B sh -c "ip netns add t && ip link add vb type veth peer name vt && ip link set vt netns t && ip -6 addr add fd00:1::5/64 dev vb nodad && ip link set vb up && ip netns exec t sh -c 'ip link set lo up; ip link set vt up; ip -6 addr add fd00:1::4/64 dev vt nodad; ip -6 addr add fd00:9::9/128 dev lo nodad' && ip -6 route add default via fd00:1::4 dev vb && ip tuntap add dev jt0 mode tun user 65534 && ip addr add 10.9.0.2/24 dev jt0 && ip link set jt0 up" > /dev/null 2>&1 || { echo "omitido  este entorno no permite espacios de red dentro del contenedor"; exit 0; }
echos() { docker exec $B ip netns exec t sh -c "awk '/Icmp6InEchos / {print \$2}' /proc/net/snmp6"; }
e0=$(echos); docker exec $B ping6 -c 2 -W 1 fd00:9::9 > /dev/null 2>&1; e1=$(echos)
[ $((e1 - e0)) -ge 2 ] && ok "LÍNEA BASE: sin el túnel completo el ping IPv6 de B llega a T ($((e1 - e0)) ecos): la prueba ve el tráfico IPv6" || fail "línea base: a T llegaron $((e1 - e0)) ecos (la prueba no distinguiría una fuga)"
docker exec $B sh -c "/fullroute.sh up jt0 51820" || { fail "fullroute up"; exit 1; }
e0=$(echos); out=$(docker exec $B ping6 -c 2 -W 1 fd00:9::9 2>&1); pr=$?; e1=$(echos)
[ $pr -ne 0 ] && [ "$e0" = "$e1" ] && ok "con el túnel completo el IPv6 NO sale: el ping falla ($(echo "$out" | tail -1 | cut -c1-60)) y a T no le llega ni un eco" || fail "fuga de IPv6: ping=$pr, ecos en T $e0 -> $e1"
docker exec $B sh -c "/fullroute.sh down jt0 51820"
e0=$(echos); docker exec $B ping6 -c 2 -W 1 fd00:9::9 > /dev/null 2>&1; e1=$(echos)
[ $((e1 - e0)) -ge 2 ] && ok "tras «fullroute.sh down» el IPv6 vuelve a salir por la ruta normal (el bloqueo es solo del túnel completo)" || fail "tras down: a T llegaron $((e1 - e0)) ecos"
exit $bad
