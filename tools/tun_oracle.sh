#!/bin/sh
# V1: tráfico REAL por «jvpn up». Dos contenedores con NET_ADMIN: A con el WireGuard del KERNEL (10.9.0.1) y B con jvpn (interfaz TUN, 10.9.0.2) corriendo como un usuario sin privilegios.
# Se prueba ping en los dos sentidos, 20 MB por TCP con suma de comprobación, el usuario sin privilegios, el descarte de orígenes suplantados y un reinicio de jvpn. Necesita docker; si no hay, se omite.
cd "$(dirname "$0")/.."
command -v docker > /dev/null 2>&1 || { echo "omitido  sin docker no hay donde crear una interfaz TUN con privilegios"; exit 0; }
[ -x build/jvpn ] || ./build.sh > /dev/null || exit 1
docker image inspect jvpn-wgkernel:test > /dev/null 2>&1 || docker build -q -t jvpn-wgkernel:test tools/wgkernel > /dev/null || { echo "FALLA  no se pudo construir la imagen del comparador"; exit 1; }
T=$(mktemp -d /tmp/jvpn_tun.XXXXXX); bad=0
ok() { echo "ok     $1"; }
fail() { echo "FALLA  $1"; bad=1; }
A=jvpn_tunA_$$; B=jvpn_tunB_$$
cleanup() { docker rm -f $A $B > /dev/null 2>&1; rm -rf $T; }
trap cleanup EXIT
build/jvpn genkey > $T/key; OURPUB=$(build/jvpn pubkey $T/key); chmod 644 $T/key
docker run -d --rm --name $A --cap-add NET_ADMIN jvpn-wgkernel:test > /dev/null || { echo "FALLA  no arranca A"; exit 1; }
docker run -d --rm --name $B --cap-add NET_ADMIN --device /dev/net/tun jvpn-wgkernel:test > /dev/null || { echo "FALLA  no arranca B"; exit 1; }
AIP=$(docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' $A); BIP=$(docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' $B)
KPRIV=$(docker exec $A wg genkey); KPUB=$(echo "$KPRIV" | docker exec -i $A wg pubkey)
docker exec $A sh -c "echo '$KPRIV' > /k && ip link add wg0 type wireguard && wg set wg0 private-key /k listen-port 51820 peer '$OURPUB' allowed-ips 10.9.0.0/24 endpoint $BIP:51821 && ip addr add 10.9.0.1/24 dev wg0 && ip addr add 10.9.0.77/32 dev wg0 && ip link set wg0 up mtu 1420" || { fail "no se configura A"; exit 1; }
docker cp build/jvpn $B:/jvpn > /dev/null; docker cp $T/key $B:/key > /dev/null
start_jvpn() { docker exec -d $B sh -c "/jvpn up /key '$KPUB' --tun jt0 --allowed 10.9.0.1/32 --endpoint $AIP:51820 --listen 51821 --user 65534 -v > /log 2>&1"; }
start_jvpn
i=0; while [ $i -lt 30 ] && ! docker exec $B grep -q "privilegios soltados" /log 2>/dev/null; do sleep 0.3; i=$((i+1)); done
docker exec $B grep -q "privilegios soltados (uid 65534)" /log && ok "jvpn crea la TUN con privilegios y los suelta antes del primer paquete" || { fail "no arranca: $(docker exec $B cat /log)"; exit 1; }
docker exec $B sh -c "ip addr add 10.9.0.2/24 dev jt0 && ip link set jt0 up mtu 1420" || { fail "no se configura jt0"; exit 1; }
PID=$(docker exec $B pidof jvpn)
uid=$(docker exec $B sh -c "grep '^Uid:' /proc/$PID/status | cut -f2-5 | tr '\t' ' '")
[ "$uid" = "65534 65534 65534 65534" ] && ok "el proceso corre con uid 65534 en los cuatro (real, efectivo, guardado, sistema de archivos)" || fail "uid: $uid"
caps=$(docker exec $B sh -c "grep '^CapEff:' /proc/$PID/status | cut -f2")
[ "$caps" = "0000000000000000" ] && ok "sin ninguna capacidad efectiva (CapEff = 0)" || fail "capacidades: $caps"
out=$(docker exec $A ping -c 3 -W 3 10.9.0.2 2>&1)
echo "$out" | grep -q "3 packets received" && ok "el kernel (A) hace ping a la TUN de jvpn y recibe respuesta: 3 de 3 (ICMP real, el kernel de B contesta)" || fail "ping A→B: $out"
out=$(docker exec $B ping -c 3 -W 3 10.9.0.1 2>&1)
echo "$out" | grep -q "3 packets received" && ok "ping de B (por la TUN y jvpn) al kernel de A: 3 de 3" || fail "ping B→A: $out"
# TCP: 20 MB con suma de comprobación
docker exec -d $B sh -c "nc -l -p 5001 > /rx"
sleep 1
docker exec $A sh -c "head -c 20000000 /dev/urandom > /tx; sha256sum /tx | cut -d' ' -f1 > /tx.sum; nc -w 3 10.9.0.2 5001 < /tx"
sleep 2
s1=$(docker exec $A cat /tx.sum); s2=$(docker exec $B sh -c "sha256sum /rx | cut -d' ' -f1")
[ "$s1" = "$s2" ] && [ -n "$s1" ] && ok "20 MB por TCP a través del túnel llegan idénticos (sha256 coincide; MTU 1420, pérdida cero)" || fail "TCP: $s1 / $s2"
# suplantación: A envía con origen 10.9.0.77, que jvpn NO permite (solo 10.9.0.1/32)
rx0=$(docker exec $B sh -c "cat /sys/class/net/jt0/statistics/rx_packets")
docker exec $A ping -c 2 -W 2 -I 10.9.0.77 10.9.0.2 > /dev/null 2>&1
rx1=$(docker exec $B sh -c "cat /sys/class/net/jt0/statistics/rx_packets")
[ "$rx0" = "$rx1" ] && ok "un paquete con origen suplantado (10.9.0.77, fuera de las direcciones permitidas) se descarta: la TUN no recibe ni uno (rx_packets sin cambio)" || fail "suplantación: tx_packets $rx0 -> $rx1"
out=$(docker exec $A ping -c 1 -W 3 10.9.0.2 2>&1); echo "$out" | grep -q "1 packets received" && ok "y el tráfico legítimo sigue pasando después" || fail "tras la suplantación: $out"
# destino fuera de las direcciones permitidas: jvpn no lo envía (A no recibe nada en wg0)
a0=$(docker exec $A sh -c "cat /sys/class/net/wg0/statistics/rx_packets")
docker exec $B ping -c 2 -W 1 10.9.0.99 > /dev/null 2>&1
a1=$(docker exec $A sh -c "cat /sys/class/net/wg0/statistics/rx_packets")
[ "$a0" = "$a1" ] && ok "un paquete hacia una dirección que el par no tiene permitida (10.9.0.99) no se envía por el túnel" || fail "destino no permitido: rx de wg0 $a0 -> $a1"
# COOKIES al revés: jvpn responde 'bajo carga' (--force-cookies): el kernel INICIA, recibe la respuesta de cookie, repite con MAC2 y el túnel se establece
docker exec $B sh -c "kill \$(pidof jvpn)"; sleep 1
docker exec $B sh -c "ip link del jt0" > /dev/null 2>&1
docker exec -d $B sh -c "/jvpn up /key '$KPUB' --tun jt0 --allowed 10.9.0.1/32 --listen 51821 --user 65534 --force-cookies -v > /log 2>&1"
i=0; while [ $i -lt 30 ] && ! docker exec $B grep -q "privilegios soltados" /log 2>/dev/null; do sleep 0.3; i=$((i+1)); done
docker exec $B sh -c "ip addr add 10.9.0.2/24 dev jt0 && ip link set jt0 up mtu 1420"
out=$(docker exec $A sh -c "wg set wg0 peer '$OURPUB' remove; wg set wg0 peer '$OURPUB' allowed-ips 10.9.0.0/24 endpoint $BIP:51821; ping -c 1 -W 20 10.9.0.2" 2>&1)
echo "$out" | grep -q "1 packets received" && docker exec $B grep -q "bajo carga: respuesta de cookie enviada" /log && docker exec $B grep -q "apretón de manos aceptado" /log && ok "COOKIES en el respondedor: jvpn (forzado a bajo carga) contesta con una cookie, el KERNEL la abre, repite con MAC2 y el ping pasa" || fail "cookies de jvpn: $out / $(docker exec $B cat /log)"
# reinicio de jvpn: nueva sesión, el par antiguo del kernel la reconoce
docker exec $B sh -c "kill \$(pidof jvpn)"; sleep 1
docker exec $B sh -c "ip link show jt0" > /dev/null 2>&1 && docker exec $B sh -c "ip link del jt0" > /dev/null 2>&1
start_jvpn
i=0; while [ $i -lt 30 ] && ! docker exec $B grep -q "privilegios soltados" /log 2>/dev/null; do sleep 0.3; i=$((i+1)); done
docker exec $B sh -c "ip addr add 10.9.0.2/24 dev jt0 && ip link set jt0 up mtu 1420"
sleep 1
out=$(docker exec $A ping -c 3 -W 3 10.9.0.2 2>&1)
echo "$out" | grep -q "3 packets received" && ok "tras matar y relanzar jvpn el túnel se restablece (nuevo apretón de manos): 3 de 3" || fail "reinicio: $out"
exit $bad
