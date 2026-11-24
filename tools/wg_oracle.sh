#!/bin/sh
# Prueba de interoperabilidad con el WireGuard del KERNEL (en un contenedor con NET_ADMIN): jvpn inicia y el kernel responde (con pings por el túnel), y el kernel inicia y jvpn responde.
# Salida: líneas «ok» / «FALLA». Necesita docker; si no hay, se omite (código 0 con aviso).
cd "$(dirname "$0")/.."
command -v docker > /dev/null 2>&1 || { echo "omitido  sin docker no hay WireGuard del kernel con que comparar"; exit 0; }
[ -x build/jvpn ] || ./build.sh > /dev/null || exit 1
docker image inspect jvpn-wgkernel:test > /dev/null 2>&1 || docker build -q -t jvpn-wgkernel:test tools/wgkernel > /dev/null || { echo "FALLA  no se pudo construir la imagen del comparador"; exit 1; }
T=$(mktemp -d /tmp/jvpn_wg.XXXXXX); bad=0
ok() { echo "ok     $1"; }
fail() { echo "FALLA  $1"; bad=1; }
build/jvpn genkey > $T/key; chmod 600 $T/key
OURPUB=$(build/jvpn pubkey $T/key)
NAME=jvpn_wgk_$$
docker run -d --rm --name $NAME --cap-add NET_ADMIN -p 127.0.0.1:51820:51820/udp jvpn-wgkernel:test > /dev/null || { echo "FALLA  no arranca el contenedor"; exit 1; }
KPRIV=$(docker exec $NAME wg genkey)
KPUB=$(echo "$KPRIV" | docker exec -i $NAME wg pubkey)
docker exec $NAME sh -c "echo '$KPRIV' > /k && ip link add wg0 type wireguard && wg set wg0 private-key /k listen-port 51820 peer '$OURPUB' allowed-ips 10.9.0.2/32 && ip addr add 10.9.0.1/24 dev wg0 && ip link set wg0 up" || { fail "no se configura wg0 en el contenedor"; docker rm -f $NAME > /dev/null; exit 1; }
# 1) jvpn INICIA; el kernel responde y contesta pings
out=$(timeout 30 build/jvpn probe $T/key "$KPUB" 127.0.0.1:51820 10.9.0.2 10.9.0.1 5 2>&1); rc=$?
[ $rc -eq 0 ] && echo "$out" | grep -q "apretón de manos completo" && [ "$(echo "$out" | grep -c 'respuesta de')" = 5 ] && ok "jvpn inicia: apretón de manos con el WireGuard del KERNEL y 5 pings contestados por el túnel" || fail "jvpn inicia: $out"
docker exec $NAME wg show wg0 | grep -q "latest handshake" && ok "el kernel registra el apretón de manos (latest handshake)" || fail "el kernel no registra el apretón de manos"
# 2) clave del par equivocada: no hay respuesta
out=$(timeout 30 build/jvpn probe $T/key "$(build/jvpn genkey | tr -d '\n' > $T/x; build/jvpn pubkey $T/x)" 127.0.0.1:51820 10.9.0.2 10.9.0.1 1 2>&1); rc=$?
[ $rc -ne 0 ] && echo "$out" | grep -q "sin respuesta" && ok "con otra clave pública del par el kernel NO responde (MAC1 inválido)" || fail "clave equivocada: rc=$rc $out"
# 2b) COOKIES: el kernel bajo carga (inundado con iniciaciones falsas de MAC1 válido) contesta con respuestas de cookie; jvpn las abre (XChaCha20-Poly1305) y repite con MAC2 válido
KIP=$(docker inspect -f "{{.NetworkSettings.Networks.bridge.IPAddress}}" $NAME)
out=$(timeout 60 build/jvpn cookie-probe $T/key "$KPUB" $KIP:51820 20000 2>&1); rc=$?
if [ $rc -ne 0 ]; then sleep 3; out=$(timeout 60 build/jvpn cookie-probe $T/key "$KPUB" $KIP:51820 60000 2>&1); rc=$?; fi
[ $rc -eq 0 ] && echo "$out" | grep -q "cookie recibida y abierta" && echo "$out" | grep -q "el par aceptó la iniciación" && ok "COOKIES contra el kernel bajo carga: la respuesta de cookie (XChaCha20-Poly1305) se abre y con el MAC2 el kernel acepta la iniciación ($(echo "$out" | head -1 | sed "s/jvpn: //"))" || fail "cookies contra el kernel: rc=$rc $out"
sleep 3
# 3) el kernel INICIA: jvpn escucha y contesta
HOSTIP=$(docker exec $NAME ip route | awk '/default/ {print $3}')
build/jvpn listen $T/key "$KPUB" 51821 10.9.0.2 3 > $T/listen.log 2>&1 &
LP=$!
sleep 1
docker exec $NAME sh -c "wg set wg0 peer '$OURPUB' remove && wg set wg0 peer '$OURPUB' allowed-ips 10.9.0.2/32 endpoint $HOSTIP:51821 && ping -c 3 -W 3 10.9.0.2" > $T/ping.log 2>&1
sleep 1
[ "$(grep -c 'ping contestado' $T/listen.log)" = 3 ] && grep -q "3 packets received" $T/ping.log && ok "el kernel inicia: jvpn responde al apretón de manos y contesta 3 pings (ping del contenedor: 3 de 3)" || { fail "el kernel inicia: $(cat $T/listen.log) / $(tail -3 $T/ping.log)"; }
kill $LP 2>/dev/null
# 4) con clave precompartida (PSK): el kernel y jvpn la usan en los dos papeles
wg_psk=$(docker exec $NAME wg genpsk); echo "$wg_psk" > $T/psk; chmod 600 $T/psk
docker exec $NAME sh -c "echo '$wg_psk' > /psk && wg set wg0 peer '$OURPUB' remove && wg set wg0 peer '$OURPUB' allowed-ips 10.9.0.2/32 preshared-key /psk"
out=$(JVPN_PSK_FILE=$T/psk timeout 30 build/jvpn probe $T/key "$KPUB" 127.0.0.1:51820 10.9.0.2 10.9.0.1 2 2>&1); rc=$?
[ $rc -eq 0 ] && ok "con clave precompartida (PSK) jvpn inicia y el kernel responde" || fail "PSK: $out"
out=$(timeout 30 build/jvpn probe $T/key "$KPUB" 127.0.0.1:51820 10.9.0.2 10.9.0.1 1 2>&1); rc=$?
[ $rc -ne 0 ] && ok "sin la PSK que el kernel exige, el apretón de manos no se completa" || fail "sin PSK debía fallar: $out"
docker rm -f $NAME > /dev/null 2>&1
rm -rf $T
exit $bad
