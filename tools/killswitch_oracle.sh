#!/bin/sh
# R-V05 (fugas de tráfico): túnel COMPLETO con interruptor de seguridad. Tres contenedores: S (WireGuard del kernel, la salida, con reenvío), T (el «Internet»: sabe volver a 10.9.0.0/24 por S) y B (jvpn, cuyo
# tráfico por omisión va por el túnel con tools/fullroute.sh). T muestra desde qué dirección le llegan las conexiones (/proc/net/tcp). Se prueba: el tráfico sale por el túnel; si jvpn muere con la interfaz
# PERSISTENTE el tráfico se pierde y NO sale por la interfaz normal; jvpn reiniciado SIN privilegios se reune a la interfaz; y, de CONTRASTE, sin --persist al morir jvpn el tráfico SÍ se fuga (la prueba detecta la fuga).
cd "$(dirname "$0")/.."
command -v docker > /dev/null 2>&1 || { echo "omitido  sin docker no hay donde crear una interfaz TUN con privilegios"; exit 0; }
[ -x build/jvpn ] || ./build.sh > /dev/null || exit 1
docker image inspect jvpn-wgkernel:test > /dev/null 2>&1 || docker build -q -t jvpn-wgkernel:test tools/wgkernel > /dev/null || { echo "FALLA  no se pudo construir la imagen del comparador"; exit 1; }
T=$(mktemp -d /tmp/jvpn_ks.XXXXXX); bad=0
ok() { echo "ok     $1"; }
fail() { echo "FALLA  $1"; bad=1; }
S=jvpn_ksS_$$; X=jvpn_ksT_$$; B=jvpn_ksB_$$
cleanup() { docker rm -f $S $X $B > /dev/null 2>&1; rm -rf $T; }
trap cleanup EXIT
build/jvpn genkey > $T/key; OURPUB=$(build/jvpn pubkey $T/key)
docker run -d --rm --name $S --cap-add NET_ADMIN --sysctl net.ipv4.ip_forward=1 jvpn-wgkernel:test > /dev/null || { echo "FALLA  no arranca S"; exit 1; }
docker run -d --rm --name $X --cap-add NET_ADMIN --sysctl net.ipv4.ip_forward=1 jvpn-wgkernel:test > /dev/null || { echo "FALLA  no arranca T"; exit 1; }
docker run -d --rm --name $B --cap-add NET_ADMIN --device /dev/net/tun jvpn-wgkernel:test > /dev/null || { echo "FALLA  no arranca B"; exit 1; }
ipof() { docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' $1; }
SIP=$(ipof $S); XIP=$(ipof $X); BIP=$(ipof $B)
hex() { echo "$1" | awk -F. '{printf "%02X%02X%02X%02X", $4, $3, $2, $1}'; }
KP=$(docker exec $S wg genkey); KPUB=$(echo "$KP" | docker exec -i $S wg pubkey)
docker exec $S sh -c "echo '$KP' > /k && ip link add wg0 type wireguard && wg set wg0 private-key /k listen-port 51820 peer '$OURPUB' allowed-ips 10.9.0.2/32 && ip addr add 10.9.0.1/24 dev wg0 && ip link set wg0 up mtu 1420" || { fail "no se configura S"; exit 1; }
# T es el «Internet»: tiene la dirección 203.0.113.9 y es la puerta de enlace de B (una fuga llega a T desde la dirección normal de B); S llega a ella por T y T devuelve 10.9.0.0/24 por S
docker exec $X sh -c "ip addr add 203.0.113.9/32 dev lo && ip route add 10.9.0.0/24 via $SIP" || { fail "no se configura T"; exit 1; }
# el servidor del túnel tiene una dirección «de Internet» (198.51.100.1) a la que B llega por su ruta POR OMISIÓN (vía T): sin la marca del socket, esos paquetes entrarían al túnel en un bucle
docker exec $S sh -c "ip addr add 198.51.100.1/32 dev lo"
docker exec $X sh -c "ip route add 198.51.100.1/32 via $SIP" || { fail "no se configura T (ruta a S)"; exit 1; }
docker exec $S sh -c "ip route add 203.0.113.9/32 via $XIP" || { fail "no se configura S"; exit 1; }
NET=203.0.113.9
docker exec -d $X sh -c "while true; do nc -l -p 7000 > /dev/null; done"
cat > $T/wg.conf <<EOC
[Interface]
PrivateKey = $(cat $T/key)
ListenPort = 51821
FwMark = 51820

[Peer]
PublicKey = $KPUB
AllowedIPs = 0.0.0.0/0
Endpoint = 198.51.100.1:51820
EOC
chmod 600 $T/wg.conf
docker cp build/jvpn $B:/jvpn > /dev/null; docker cp $T/wg.conf $B:/wg.conf > /dev/null; docker cp tools/fullroute.sh $B:/fullroute.sh > /dev/null
docker exec $B sh -c "ip route replace default via $XIP dev eth0"
start() { docker exec -d $B sh -c "/jvpn up /wg.conf --tun jt0 --user 65534 $1 -v > /log 2>&1"; i=0; while [ $i -lt 30 ] && ! docker exec $B grep -q "privilegios soltados\|ya corre sin privilegios" /log 2>/dev/null; do sleep 0.3; i=$((i+1)); done; }
# una conexión que se MANTIENE 3 s: mientras dura, T la ve en /proc/net/tcp (estado 01) con la dirección de origen con que le llegó
connect() { docker exec -d $B sh -c "(sleep 3 | nc -w 4 $NET 7000) > /dev/null 2>&1"; sleep 1.5; }
seen() { docker exec $X sh -c "cat /proc/net/tcp /proc/net/tcp6 | grep -c '$(hex $1):[0-9A-F]\\{4\\} 0[1-9] '" 2>/dev/null; }
settle() { sleep 3.5; }
# 0) SIN VENTANA: la interfaz persistente y las rutas se crean ANTES de arrancar jvpn (ip tuntap), con el túnel completo desde el primer instante: hasta que jvpn arranque el tráfico se pierde, no sale en claro
docker exec $B sh -c "ip tuntap add dev jt0 mode tun user 65534 && ip addr add 10.9.0.2/24 dev jt0 && ip link set jt0 up mtu 1420 && /fullroute.sh up jt0 51820" || { fail "no se prepara la interfaz persistente"; exit 1; }
a0=$(seen 10.9.0.2); b0=$(seen $BIP)
connect; a1=$(seen 10.9.0.2); b1=$(seen $BIP); settle
docker exec $B ping -c 2 -W 1 $NET > /dev/null 2>&1; pr=$?
[ "$a0" = "$a1" ] && [ "$b0" = "$b1" ] && [ $pr -ne 0 ] && ok "SIN VENTANA: con las rutas puestas antes de arrancar jvpn, hasta que arranca el tráfico no llega a T por ningún camino (ni en claro ni por el túnel)" || fail "ventana al arrancar: T ve directo $b0->$b1, túnel $a0->$a1, ping=$pr"
# 1) túnel completo con interfaz persistente (jvpn se une a la que ya existe)
start "--persist"
docker exec $B grep -q "PERSISTENTE" /log && ok "jvpn hace la interfaz persistente (dueño: el usuario sin privilegios) y suelta los privilegios" || { fail "no arranca persistente: $(docker exec $B cat /log)"; exit 1; }
sleep 2
connect; a=$(seen 10.9.0.2); b=$(seen $BIP); settle
[ "$a" -ge 1 ] && [ "$b" = 0 ] && ok "con el túnel completo, la conexión a «Internet» llega a T desde 10.9.0.2 (salió por el túnel y la salida S) y no desde la dirección normal de B" || fail "túnel completo: visto-por-túnel=$a visto-directo=$b"
# 1b) DNS (R-V05): consultas UDP/53 con el túnel completo. S (10.9.0.1, DENTRO del túnel) y T (203.0.113.9, «Internet», y su dirección de la red local) corren un servidor DNS de prueba que anota el origen de cada consulta
[ -x build/dnsstub ] || ../../../compiladorELF/1.0.1/src/jelf.sh tools/DnsStub.java -o build/dnsstub > /dev/null 2>&1
docker cp build/dnsstub $S:/dnsstub > /dev/null; docker cp build/dnsstub $X:/dnsstub > /dev/null
docker exec -d $S sh -c "/dnsstub 53 10.9.0.1 > /dns.log 2>&1"; docker exec -d $X sh -c "/dnsstub 53 $NET > /dns.log 2>&1"; docker exec -d $X sh -c "/dnsstub 53 $XIP > /dns2.log 2>&1"
sleep 1
lookup() { docker exec $B sh -c "timeout 5 nslookup nombre.prueba $1 > /dev/null 2>&1; echo \$?"; }
qn() { docker exec $1 sh -c "cat /dns.log /dns2.log 2>/dev/null | grep -c '^q $2\$'" 2>/dev/null; }
s0=$(qn $S 10.9.0.2); t0=$(qn $X 10.9.0.2); tb0=$(qn $X $BIP)
r=$(lookup 10.9.0.1); s1=$(qn $S 10.9.0.2); t1=$(qn $X 10.9.0.2); tb1=$(qn $X $BIP)
[ "$r" = 0 ] && [ $((s1 - s0)) -ge 1 ] && [ "$t1" = "$t0" ] && [ "$tb1" = "$tb0" ] && ok "DNS con el servidor DENTRO del túnel (10.9.0.1): la consulta llega a S desde 10.9.0.2 y a «Internet» no le llega nada" || fail "DNS por el túnel: rc=$r S $s0->$s1, T(túnel) $t0->$t1, T(directo) $tb0->$tb1"
r=$(lookup $NET); t2=$(qn $X 10.9.0.2); tb2=$(qn $X $BIP)
[ "$r" = 0 ] && [ $((t2 - t1)) -ge 1 ] && [ "$tb2" = "$tb1" ] && ok "DNS con un servidor de «Internet» (203.0.113.9): la consulta sale por el túnel (T la ve desde 10.9.0.2) y no en claro desde la dirección de B" || fail "DNS a Internet: rc=$r T(túnel) $t1->$t2, T(directo) $tb1->$tb2"
r=$(lookup $XIP); tb3=$(qn $X $BIP)
[ "$r" = 0 ] && [ $((tb3 - tb2)) -ge 1 ] && ok "ADVERTENCIA CONFIRMADA: un servidor DNS en la red LOCAL (la misma subred de B) se consulta EN CLARO aunque haya túnel completo (T la ve desde la dirección de B): el DNS debe estar dentro del túnel o fuera de la subred local" || fail "DNS local: se esperaba la consulta directa (rc=$r, $tb2->$tb3): la advertencia de AUDITORIA 10 no se confirmó"
# 2) jvpn MUERE: la interfaz persiste y no hay fuga
docker exec $B sh -c "kill \$(pidof jvpn)"; sleep 1
docker exec $B sh -c "ip link show jt0" > /dev/null 2>&1 && ok "tras morir jvpn la interfaz persiste (con sus rutas)" || fail "la interfaz desapareció al morir jvpn"
a0=$(seen 10.9.0.2); b0=$(seen $BIP)
connect; b1=$(seen $BIP); a1=$(seen 10.9.0.2); settle
docker exec $B ping -c 2 -W 1 $NET > /dev/null 2>&1; pr=$?
[ "$b1" = "$b0" ] && [ "$a1" = "$a0" ] && [ $pr -ne 0 ] && ok "INTERRUPTOR: con jvpn muerto la conexión no llega a T por ningún camino (ni por el túnel ni desde la dirección normal de B) y el ping falla: sin fuga" || fail "fuga con jvpn muerto: T ve directo $b0->$b1, túnel $a0->$a1, ping=$pr"
tb0=$(qn $X $BIP); t0=$(qn $X 10.9.0.2)
r=$(lookup $NET); tb1=$(qn $X $BIP); t1=$(qn $X 10.9.0.2)
[ "$r" != 0 ] && [ "$tb0" = "$tb1" ] && [ "$t0" = "$t1" ] && ok "DNS con jvpn muerto: la consulta falla y no llega a T por ningún camino (el interruptor cubre también el DNS)" || fail "DNS con jvpn muerto: rc=$r, T(directo) $tb0->$tb1, T(túnel) $t0->$t1"
# 3) jvpn relanzado se reúne a la interfaz persistente que ya existía
docker exec -d $B sh -c "/jvpn up /wg.conf --tun jt0 --user 65534 --persist -v > /log 2>&1"
i=0; while [ $i -lt 30 ] && ! docker exec $B grep -q "privilegios soltados" /log 2>/dev/null; do sleep 0.3; i=$((i+1)); done
docker exec $B grep -q "privilegios soltados (uid 65534)" /log && ok "jvpn relanzado (con privilegios, que necesita para FwMark) se reúne a la interfaz persistente que ya existía y los suelta de nuevo" || fail "relanzamiento: $(docker exec $B cat /log)"
sleep 2
a0=$(seen 10.9.0.2); connect; a=$(seen 10.9.0.2); settle
[ "$a" -gt "$a0" ] && ok "y el tráfico vuelve a salir por el túnel (nuevo apretón de manos)" || fail "tras reiniciar: T ve $a conexiones desde 10.9.0.2"
# 4) CONTRASTE: sin --persist, al morir jvpn la interfaz y sus rutas desaparecen y el tráfico SE FUGA (la prueba detecta la fuga)
docker exec $B sh -c "kill \$(pidof jvpn)"; sleep 1
docker exec $B sh -c "/fullroute.sh down jt0 51820; ip link del jt0" > /dev/null 2>&1
start ""
docker exec $B sh -c "ip addr add 10.9.0.2/24 dev jt0 && ip link set jt0 up mtu 1420 && /fullroute.sh up jt0 51820"
sleep 1
docker exec $B sh -c "kill \$(pidof jvpn)"; sleep 1
b0=$(seen $BIP); connect; b1=$(seen $BIP); settle
[ "$b1" -gt "$b0" ] && ok "CONTRASTE: sin --persist, al morir jvpn el tráfico sale por la ruta normal y T lo ve desde la dirección de B: es la fuga que el interruptor evita (y la prueba la detecta)" || fail "el contraste no mostró la fuga (T ve $b1 conexiones desde la dirección de B): la prueba no distinguiría una fuga"
exit $bad
