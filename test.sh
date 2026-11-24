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
build/jvpn help | grep -q "órdenes: version, help" && ok "help lista las órdenes" || fail "help"
out=$(build/jvpn nada 2>&1); rc=$?
[ $rc -eq 2 ] && echo "$out" | grep -q "orden desconocida «nada»; use «jvpn help»" && ok "una orden desconocida se rechaza con la causa y qué hacer (código 2)" || fail "orden desconocida (código $rc)"
[ -f RIESGOS.md ] && grep -q "^| R-" RIESGOS.md && ok "RIESGOS.md existe y tiene riesgos anotados ($(grep -c '^| R-' RIESGOS.md))" || fail "RIESGOS.md"
[ $bad = 0 ] && echo "jvpn: todo bien" || { echo "jvpn: HAY FALLOS"; exit 1; }
