#!/bin/sh
# V3: rendimiento de extremo a extremo con iperf3 (TCP, un flujo y varios), dos contenedores en la MISMA máquina (WSL2 anidado: las cifras son de esta máquina, no generales).
#   (1) kernel <-> kernel: la línea base (WireGuard del kernel en los dos lados)
#   (2) jvpn <-> kernel: jvpn en B (interfaz TUN, sin privilegios), el kernel en A
# Mide Mbit/s en los dos sentidos, y para jvpn la CPU que gastó y su memoria residente. Uso: tools/bench_tunnel.sh [segundos]. Necesita docker.
cd "$(dirname "$0")/.."
SEC=${1:-8}
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
docker exec -d $B sh -c "/jvpn up /wg.conf --tun jt0 --user 65534 $JVPN_OPTS > /log 2>&1"
i=0; while [ $i -lt 30 ] && ! docker exec $B grep -q "privilegios soltados" /log 2>/dev/null; do sleep 0.3; i=$((i+1)); done
docker exec $B sh -c "ip addr add 10.9.0.2/24 dev jt0 && ip link set jt0 up mtu 1420"
docker exec $A ping -c 2 -W 3 10.9.0.2 > /dev/null 2>&1; docker exec $K ping -c 2 -W 3 10.9.0.1 > /dev/null 2>&1
docker exec -d $A sh -c "iperf3 -s -1 -p 5201 > /dev/null 2>&1"
mbit() { echo "$1" | grep "receiver" | awk '{print $(NF-2)" "$(NF-1)}'; }
iperf() { # cliente servidor-ip flags
  docker exec -d $A sh -c "iperf3 -s -1 -p 5201 > /dev/null 2>&1"; sleep 0.7
  docker exec $1 iperf3 -c $2 -p 5201 -t $SEC $3 2>&1
}
echo "== iperf3 TCP, $SEC s por medición (WSL2 anidado, ambos extremos en la misma máquina)"
for run in 1 2; do
  r=$(iperf $K 10.9.0.1 ""); echo "kernel -> kernel      (1 flujo, subida):  $(mbit "$r")"
  r=$(iperf $K 10.9.0.1 "-R"); echo "kernel <- kernel      (1 flujo, bajada):  $(mbit "$r")"
done
PID=$(docker exec $B pidof jvpn)
c0u=$(docker exec $B sh -c "awk '{print \$14}' /proc/$PID/stat"); c0s=$(docker exec $B sh -c "awk '{print \$15}' /proc/$PID/stat")
for run in 1 2; do
  r=$(iperf $B 10.9.0.1 ""); echo "jvpn   -> kernel      (1 flujo, subida):  $(mbit "$r")"
  r=$(iperf $B 10.9.0.1 "-R"); echo "jvpn   <- kernel      (1 flujo, bajada):  $(mbit "$r")"
done
r=$(iperf $B 10.9.0.1 "-P 4"); echo "jvpn   -> kernel      (4 flujos, subida): $(mbit "$r")"
c1u=$(docker exec $B sh -c "awk '{print \$14}' /proc/$PID/stat"); c1s=$(docker exec $B sh -c "awk '{print \$15}' /proc/$PID/stat")
rss=$(docker exec $B sh -c "grep VmRSS /proc/$PID/status | awk '{print \$2}'")
echo "jvpn: CPU en las 5 mediciones: modo usuario $((c1u - c0u)) ticks, modo núcleo (llamadas al sistema, y el trabajo del receptor que corre en la misma CPU por la veth) $((c1s - c0s)) ticks (100 por segundo); memoria residente: $rss kB; binario: $(wc -c < build/jvpn) bytes"
docker exec $B grep "TUN:" /log 2>/dev/null | tail -4
