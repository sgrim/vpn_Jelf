#!/bin/sh
# Pruebas de jvpn: compila, vigila las reglas fijas del proyecto y prueba el esqueleto.
cd "$(dirname "$0")" || exit 1
./build.sh > /dev/null || { echo "FALLA build.sh"; exit 1; }
bad=0
ok() { echo "ok     $1"; }
fail() { echo "FALLA  $1"; bad=1; }
# reglas: cabecera de copyright, UTF-8 sin BOM, sin java.util, identificadores en inglés
r=$(git ls-files --cached --others --exclude-standard '*.java' '*.md' '*.sh' '*.bat' '*.c' '*.cpp' '*.h' '*.txt' 'LICENSE' '.gitignore' 'Dockerfile' | xargs build/CheckRules 2>&1); rc=$?
if [ $rc -eq 0 ]; then ok "reglas ($(echo "$r" | tail -1))"; else fail "reglas"; echo "$r" | head -5 | sed 's/^/         /'; fi
[ "$(build/jvpn version)" = "jvpn 1.0.1" ] && ok "version" || fail "version"
build/jvpn help | grep -q "órdenes: version, help, genkey" && ok "help lista las órdenes" || fail "help"
out=$(build/jvpn nada 2>&1); rc=$?
[ $rc -eq 2 ] && echo "$out" | grep -q "orden desconocida «nada»; use «jvpn help»" && ok "una orden desconocida se rechaza con la causa y qué hacer (código 2)" || fail "orden desconocida (código $rc)"
s=$(timeout 200 build/jvpn selftest 2>&1); echo "$s" | grep -q "^FALLA" && { fail "selftest"; echo "$s" | grep "^FALLA" | head -5; } || ok "$(echo "$s" | tail -1)"
K=$(mktemp -d /tmp/jvpn_k.XXXXXX); build/jvpn genkey > $K/k; [ $(wc -c < $K/k) = 45 ] && [ "$(build/jvpn pubkey $K/k | wc -c)" = 45 ] && ok "genkey y pubkey dan claves de 44 caracteres" || fail "genkey/pubkey"
# vector oficial de X25519 (RFC 7748 6.1): la clave pública de Alice
echo "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=" > $K/a; [ "$(build/jvpn pubkey $K/a)" = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=" ] && ok "pubkey: el vector de RFC 7748 (Alice)" || fail "pubkey: vector de RFC 7748"
rm -rf $K
$(dirname "$0")/tools/wg_oracle.sh > /tmp/jvpn_oracle.txt 2>&1; cat /tmp/jvpn_oracle.txt; grep -q "^FALLA" /tmp/jvpn_oracle.txt && bad=1
$(dirname "$0")/tools/killswitch_oracle.sh > /tmp/jvpn_ks.txt 2>&1; cat /tmp/jvpn_ks.txt; grep -q "^FALLA" /tmp/jvpn_ks.txt && bad=1
$(dirname "$0")/tools/tun_oracle.sh > /tmp/jvpn_tun.txt 2>&1; cat /tmp/jvpn_tun.txt; grep -q "^FALLA" /tmp/jvpn_tun.txt && bad=1
[ -f RIESGOS.md ] && grep -q "^| R-" RIESGOS.md && ok "RIESGOS.md existe y tiene riesgos anotados ($(grep -c '^| R-' RIESGOS.md))" || fail "RIESGOS.md"
[ $bad = 0 ] && echo "jvpn: todo bien" || { echo "jvpn: HAY FALLOS"; exit 1; }
