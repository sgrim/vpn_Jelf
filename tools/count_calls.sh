#!/bin/sh
# Cuenta las llamadas al sistema por paquete de jvpn en una sola fase (subida o bajada) con iperf3: usa los contadores de «jvpn up -v». Uso: tools/count_calls.sh [up|down] [segundos]
# Las cifras son de este banco (WSL2 anidado, receptor en la misma CPU). Necesita docker.
PHASE=${1:-up}
# Mide Mbit/s en los dos sentidos, y para jvpn la CPU que gastó y su memoria residente. Uso: tools/bench_tunnel.sh [segundos]. Necesita docker.
cd "$(dirname "$0")/.."
SEC=${2:-6}
command -v docker > /dev/null 2>&1 || { echo "omitido  sin docker"; exit 0; }
[ -x build/jvpn ] || ./build.sh > /dev/null || exit 1
docker image inspect jvpn-wgkernel:test > /dev/null 2>&1 || docker build -q -t jvpn-wgkernel:test tools/wgkernel > /dev/null
T=$(mktemp -d /tmp/jvpn_bt.XXXXXX)
A=jvpn_btA_$$; B=jvpn_btB_$$; K=jvpn_btK_$$
cleanup() { docker rm -f $A $B $K > /dev/null 2>&1; rm -rf $T; }
trap cleanup EXIT
for c in $A $K; do docker run -d --rm --name $c --cap-add NET_ADMIN jvpn-wgkernel:test > /dev/null; done
docker run -d --rm --name $B --cap-add NET_ADMIN --device /dev/net/tun jvpn-wgkernel:test > /dev/null
ipof() { docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' $1; }
AIP=$(ipof $A); BIP=$(ipof $B); KIP=$(ipof $K)
kp() { docker exec $1 wg genkey; }
KA=$(kp $A); KAP=$(echo "$KA" | docker exec -i $A wg pubkey)
KK=$(kp $K); KKP=$(echo "$KK" | docker exec -i $K wg pubkey)
build/jvpn genkey > $T/key; JPUB=$(build/jvpn pubkey $T/key)
# (1) kernel <-> kernel: A (10.9.0.1) y K (10.9.0.3)
docker exec $A sh -c "echo '$KA' > /k && ip link add wg0 type wireguard && wg set wg0 private-key /k listen-port 51820 peer '$KKP' allowed-ips 10.9.0.3/32 endpoint $KIP:51820 peer '$JPUB' allowed-ips 10.9.0.2/32 endpoint $BIP:51821 && ip addr add 10.9.0.1/24 dev wg0 && ip link set wg0 up mtu 1420"
docker exec $K sh -c "echo '$KK' > /k && ip link add wg0 type wireguard && wg set wg0 private-key /k listen-port 51820 peer '$KAP' allowed-ips 10.9.0.1/32 endpoint $AIP:51820 && ip addr add 10.9.0.3/24 dev wg0 && ip link set wg0 up mtu 1420"
# (2) jvpn en B
cat > $T/wg.conf <<EOC
[Interface]
PrivateKey = $(cat $T/key)
ListenPort = 51821

[Peer]
PublicKey = $KAP
AllowedIPs = 10.9.0.1/32
Endpoint = $AIP:51820
EOC
chmod 600 $T/wg.conf
docker cp build/jvpn $B:/jvpn > /dev/null; docker cp $T/wg.conf $B:/wg.conf > /dev/null
docker exec -d $B sh -c "/jvpn up /wg.conf --tun jt0 --user 65534 -v $JVPN_OPTS > /log 2>&1"
i=0; while [ $i -lt 30 ] && ! docker exec $B grep -q "privilegios soltados" /log 2>/dev/null; do sleep 0.3; i=$((i+1)); done
docker exec $B sh -c "ip addr add 10.9.0.2/24 dev jt0 && ip link set jt0 up mtu 1420"
docker exec $A ping -c 2 -W 3 10.9.0.2 > /dev/null 2>&1; docker exec $K ping -c 2 -W 3 10.9.0.1 > /dev/null 2>&1
docker exec -d $A sh -c "iperf3 -s -1 -p 5201 > /dev/null 2>&1"
mbit() { echo "$1" | grep "receiver" | awk '{print $(NF-2)" "$(NF-1)}'; }
docker exec -d $A sh -c "iperf3 -s -1 -p 5201 > /dev/null 2>&1"; sleep 0.7
sleep 2.5 # que pase una línea de estadísticas antes de medir
l0=$(docker exec $B grep "TUN:" /log | tail -1)
if [ "$PHASE" = down ]; then r=$(docker exec $B iperf3 -c 10.9.0.1 -p 5201 -t $SEC -R 2>&1); else r=$(docker exec $B iperf3 -c 10.9.0.1 -p 5201 -t $SEC 2>&1); fi
sleep 2.2
l1=$(docker exec $B grep "TUN:" /log | tail -1)
echo "fase: $PHASE, $(mbit "$r")"
num() { echo "$1" | sed 's/[^0-9]/ /g' | awk -v k=$2 '{print $k}'; }
for i in 1 2 3 4 5 6 7 8 9; do eval "a$i=$(num "$l0" $i)"; eval "b$i=$(num "$l1" $i)"; done
# orden de los números: 1 lecturas, 2 partidos, 3 escrituras, 4 recvmmsg, 5 datagramas recibidos, 6 sendmmsg, 7 datagramas enviados, 8 esperas
d() { echo $(( $2 - $1 )); }
rd=$(d $a1 $b1); wr=$(d $a3 $b3); rc=$(d $a4 $b4); rp=$(d $a5 $b5); sc=$(d $a6 $b6); sp=$(d $a7 $b7); wt=$(d $a8 $b8)
echo "en el intervalo: $rd lecturas de la TUN, $wr escrituras en la TUN, $rc recvmmsg ($rp datagramas), $sc sendmmsg ($sp datagramas), $wt esperas"
pk=$(( rp > sp ? rp : sp )); [ $pk -gt 0 ] && echo "por datagrama de datos: lecturas TUN $(echo "scale=2; $rd/$pk" | bc), escrituras TUN $(echo "scale=2; $wr/$pk" | bc), recvmmsg $(echo "scale=3; $rc/$pk" | bc), sendmmsg $(echo "scale=3; $sc/$pk" | bc), esperas $(echo "scale=3; $wt/$pk" | bc)"
