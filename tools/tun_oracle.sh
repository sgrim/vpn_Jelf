#!/bin/sh
# V1/V2: tráfico REAL por «jvpn up CONFIG» con DOS pares. Tres contenedores con NET_ADMIN: A y A2 con el WireGuard del KERNEL (10.9.0.1 y 10.9.1.1) y B con jvpn (interfaz TUN, 10.9.0.2 y 10.9.1.2) corriendo como un
# usuario sin privilegios. Se prueba: configuración con permisos, ping en los dos sentidos con los dos pares, 20 MB por TCP con suma de comprobación, el usuario sin privilegios, el descarte de orígenes suplantados
# (también el de un par que usa las direcciones de OTRO par), el enrutamiento por destino, las cookies al revés y un reinicio. Necesita docker; si no hay, se omite.
cd "$(dirname "$0")/.."
command -v docker > /dev/null 2>&1 || { echo "omitido  sin docker no hay donde crear una interfaz TUN con privilegios"; exit 0; }
[ -x build/jvpn ] || ./build.sh > /dev/null || exit 1
docker image inspect jvpn-wgkernel:test > /dev/null 2>&1 || docker build -q -t jvpn-wgkernel:test tools/wgkernel > /dev/null || { echo "FALLA  no se pudo construir la imagen del comparador"; exit 1; }
T=$(mktemp -d /tmp/jvpn_tun.XXXXXX); bad=0
ok() { echo "ok     $1"; }
fail() { echo "FALLA  $1"; bad=1; }
A=jvpn_tunA_$$; A2=jvpn_tunA2_$$; B=jvpn_tunB_$$
cleanup() { docker rm -f $A $A2 $B > /dev/null 2>&1; rm -rf $T; }
trap cleanup EXIT
build/jvpn genkey > $T/key; OURPUB=$(build/jvpn pubkey $T/key)
for c in $A $A2; do docker run -d --rm --name $c --cap-add NET_ADMIN jvpn-wgkernel:test > /dev/null || { echo "FALLA  no arranca $c"; exit 1; }; done
docker run -d --rm --name $B --cap-add NET_ADMIN --device /dev/net/tun jvpn-wgkernel:test > /dev/null || { echo "FALLA  no arranca B"; exit 1; }
ipof() { docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' $1; }
AIP=$(ipof $A); A2IP=$(ipof $A2); BIP=$(ipof $B)
K1=$(docker exec $A wg genkey); K1P=$(echo "$K1" | docker exec -i $A wg pubkey)
K2=$(docker exec $A2 wg genkey); K2P=$(echo "$K2" | docker exec -i $A2 wg pubkey)
docker exec $A sh -c "echo '$K1' > /k && ip link add wg0 type wireguard && wg set wg0 private-key /k listen-port 51820 peer '$OURPUB' allowed-ips 10.9.0.0/24 endpoint $BIP:51821 && ip addr add 10.9.0.1/24 dev wg0 && ip addr add 10.9.0.77/32 dev wg0 && ip link set wg0 up mtu 1420" || { fail "no se configura A"; exit 1; }
docker exec $A2 sh -c "echo '$K2' > /k && ip link add wg0 type wireguard && wg set wg0 private-key /k listen-port 51820 peer '$OURPUB' allowed-ips 10.9.0.0/16 endpoint $BIP:51821 && ip addr add 10.9.1.1/24 dev wg0 && ip addr add 10.9.0.1/32 dev wg0 && ip link set wg0 up mtu 1420" || { fail "no se configura A2"; exit 1; }
cat > $T/wg.conf <<EOC
[Interface]
PrivateKey = $(cat $T/key)
ListenPort = 51821
Address = 10.9.0.2/24

# par 1: el kernel de A
[Peer]
PublicKey = $K1P
AllowedIPs = 10.9.0.1/32
Endpoint = $AIP:51820

[Peer]
PublicKey = $K2P
AllowedIPs = 10.9.1.1/32, 10.9.7.0/24
Endpoint = kernela2.prueba:51820
EOC
chmod 600 $T/wg.conf
docker cp build/jvpn $B:/jvpn > /dev/null; docker cp $T/wg.conf $B:/wg.conf > /dev/null
docker exec $B sh -c "echo '$A2IP kernela2.prueba' >> /etc/hosts" # el Endpoint del par 2 es un NOMBRE: jvpn lo resuelve al arrancar (con /etc/hosts de B)
# configuración con permisos abiertos: se rechaza con la causa
docker exec $B chmod 644 /wg.conf
out=$(docker exec $B timeout 5 /jvpn up /wg.conf --tun jt0 --user 65534 2>&1); rc=$?
[ $rc -ne 0 ] && echo "$out" | grep -q "chmod 600" && ok "una configuración con claves privadas legible por otros se rechaza (dice «chmod 600»)" || fail "permisos de la configuración: rc=$rc $out"
docker exec $B chmod 600 /wg.conf
start_jvpn() { docker exec -d $B sh -c "/jvpn up /wg.conf --tun jt0 --user 65534 $1 -v > /log 2>&1"; }
wait_up() { i=0; while [ $i -lt 30 ] && ! docker exec $B grep -q "privilegios soltados" /log 2>/dev/null; do sleep 0.3; i=$((i+1)); done; docker exec $B sh -c "ip addr add 10.9.0.2/24 dev jt0 && ip addr add 10.9.1.2/24 dev jt0 && ip link set jt0 up mtu 1420"; }
start_jvpn ""
wait_up
docker exec $B grep -q "privilegios soltados (uid 65534)" /log && ok "jvpn lee la configuración de dos pares, crea la TUN con privilegios y los suelta antes del primer paquete" || { fail "no arranca: $(docker exec $B cat /log)"; exit 1; }
docker exec $B grep -q "kernela2.prueba = $A2IP" /log && ok "un Endpoint con NOMBRE (kernela2.prueba) se resuelve al arrancar con /etc/hosts y el túnel con ese par funciona" || fail "Endpoint con nombre: $(docker exec $B head -3 /log)"
docker exec $B grep -q "AVISO.*Address" /log && ok "Address de la configuración se avisa y NO se aplica" || fail "no avisa de Address"
PID=$(docker exec $B pidof jvpn)
uid=$(docker exec $B sh -c "grep '^Uid:' /proc/$PID/status | cut -f2-5 | tr '\t' ' '")
[ "$uid" = "65534 65534 65534 65534" ] && ok "el proceso corre con uid 65534 en los cuatro (real, efectivo, guardado, sistema de archivos)" || fail "uid: $uid"
caps=$(docker exec $B sh -c "grep '^CapEff:' /proc/$PID/status | cut -f2")
[ "$caps" = "0000000000000000" ] && ok "sin ninguna capacidad efectiva (CapEff = 0)" || fail "capacidades: $caps"
sleep 1
out=$(docker exec $B ping -c 2 -W 3 10.9.0.1 2>&1); echo "$out" | grep -q "2 packets received" && ok "ping de B al par 1 (kernel A, 10.9.0.1) por la TUN y jvpn: 2 de 2" || fail "ping B→A: $out"
out=$(docker exec $B ping -c 2 -W 3 10.9.1.1 2>&1); echo "$out" | grep -q "2 packets received" && ok "ping de B al par 2 (kernel A2, 10.9.1.1): el paquete va al par que tiene la ruta: 2 de 2" || fail "ping B→A2: $out"
out=$(docker exec $A ping -c 2 -W 3 10.9.0.2 2>&1); echo "$out" | grep -q "2 packets received" && ok "ping del kernel A a la TUN de jvpn: 2 de 2 (el kernel de B contesta el ICMP real)" || fail "ping A→B: $out"
out=$(docker exec $A2 ping -c 2 -W 3 10.9.1.2 2>&1); echo "$out" | grep -q "2 packets received" && ok "ping del kernel A2 a la TUN de jvpn: 2 de 2" || fail "ping A2→B: $out"
# TCP: 20 MB con suma de comprobación, con el par 2
docker exec -d $B sh -c "nc -l -p 5001 > /rx"
sleep 1
docker exec $A2 sh -c "head -c 20000000 /dev/urandom > /tx; sha256sum /tx | cut -d' ' -f1 > /tx.sum; nc -w 3 10.9.1.2 5001 < /tx"
sleep 2
s1=$(docker exec $A2 cat /tx.sum); s2=$(docker exec $B sh -c "sha256sum /rx | cut -d' ' -f1")
[ "$s1" = "$s2" ] && [ -n "$s1" ] && ok "20 MB por TCP desde el par 2 llegan idénticos (sha256 coincide; MTU 1420)" || fail "TCP: $s1 / $s2"
# suplantación: A envía con origen 10.9.0.77, que jvpn NO permite para A (solo 10.9.0.1/32)
rx0=$(docker exec $B sh -c "cat /sys/class/net/jt0/statistics/rx_packets")
docker exec $A ping -c 2 -W 2 -I 10.9.0.77 10.9.0.2 > /dev/null 2>&1
rx1=$(docker exec $B sh -c "cat /sys/class/net/jt0/statistics/rx_packets")
[ "$rx0" = "$rx1" ] && ok "un paquete con origen suplantado (10.9.0.77, fuera de las rutas del par 1) se descarta: la TUN no recibe ni uno (rx_packets sin cambio)" || fail "suplantación: rx_packets $rx0 -> $rx1"
# suplantación ENTRE PARES: A2 usa la dirección 10.9.0.1, que es del par 1
rx0=$(docker exec $B sh -c "cat /sys/class/net/jt0/statistics/rx_packets")
docker exec $A2 ping -c 2 -W 2 -I 10.9.0.1 10.9.1.2 > /dev/null 2>&1
rx1=$(docker exec $B sh -c "cat /sys/class/net/jt0/statistics/rx_packets")
[ "$rx0" = "$rx1" ] && ok "un par que usa la dirección de OTRO par (A2 con origen 10.9.0.1) se descarta: cada par solo puede usar sus propias rutas" || fail "suplantación entre pares: rx_packets $rx0 -> $rx1"
out=$(docker exec $A2 ping -c 1 -W 3 10.9.1.2 2>&1); echo "$out" | grep -q "1 packets received" && ok "y el tráfico legítimo de ese par sigue pasando" || fail "tras la suplantación: $out"
# destino sin ruta (10.9.0.99 no es de ningún par) y destino de la segunda ruta del par 2 (10.9.7.0/24)
a0=$(docker exec $A sh -c "cat /sys/class/net/wg0/statistics/rx_packets"); b0=$(docker exec $A2 sh -c "cat /sys/class/net/wg0/statistics/rx_packets")
docker exec $B sh -c "ip route add 10.9.7.0/24 dev jt0 2>/dev/null; ping -c 2 -W 1 10.9.0.99" > /dev/null 2>&1
a1=$(docker exec $A sh -c "cat /sys/class/net/wg0/statistics/rx_packets")
[ "$a0" = "$a1" ] && ok "un destino que ningún par tiene permitido (10.9.0.99) no se envía a ningún kernel" || fail "destino sin ruta: rx de A $a0 -> $a1"
docker exec $B sh -c "ping -c 2 -W 1 10.9.7.5" > /dev/null 2>&1
b1=$(docker exec $A2 sh -c "cat /sys/class/net/wg0/statistics/rx_packets")
[ "$b0" != "$b1" ] && ok "un destino de la segunda ruta del par 2 (10.9.7.5) se envía a A2 (y no a A)" || fail "ruta 10.9.7.0/24 no llegó a A2"
# reinicio de jvpn y cookies al revés: jvpn responde 'bajo carga' (--force-cookies) y SIN endpoints, el kernel inicia, recibe la cookie, repite con MAC2 y el túnel se establece
docker exec $B sh -c "kill \$(pidof jvpn)"; sleep 1
docker exec $B sh -c "ip link del jt0" > /dev/null 2>&1
docker exec $B sh -c "sed -i '/^Endpoint/d' /wg.conf"
start_jvpn "--force-cookies"
wait_up
out=$(docker exec $A sh -c "ping -c 40 -W 1 10.9.0.2" 2>&1) # el kernel aún cree válida su sesión vieja: manda datos que jvpn (reiniciado, sin esa sesión) no puede abrir, y solo inicia un apretón de manos pasado su temporizador (como en WireGuard); los primeros pings se pierden
echo "$out" | grep -q "[1-9][0-9]* packets received" && docker exec $B grep -q "bajo carga: respuesta de cookie enviada" /log && docker exec $B grep -q "apretón de manos aceptado" /log && ok "COOKIES en el respondedor: jvpn (forzado a bajo carga) contesta con una cookie, el KERNEL la abre, repite con MAC2 y el ping pasa; tras matar y relanzar jvpn el túnel se restablece" || fail "cookies de jvpn: $out / $(docker exec $B cat /log) / A: $(docker exec $A wg show wg0 | tr "\n" " ") / B: $(docker exec $B ip -s link show jt0 | tr "\n" " ")"
exit $bad
