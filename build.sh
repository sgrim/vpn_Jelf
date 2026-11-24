#!/bin/sh
# Compila con jelf -> build/. El compilador es el de ../../../compiladorELF/1.0.1/src; JELF=/otra/ruta/jelf.sh lo cambia.
set -e
cd "$(dirname "$0")"
JELF="${JELF:-../../../compiladorELF/1.0.1/src/jelf.sh}"
[ -f ../../../compiladorELF/1.0.1/src/jelf-1.0.1.jar ] || (cd ../../../compiladorELF/1.0.1/src && ./build.sh > /dev/null)
mkdir -p build
# la criptografía de edge_Jelf (SHA-2, Ed25519, ML-KEM, y lo que vaya llegando) se compilará junto con el proyecto, sin copiarla
"$JELF" vpn/Jvpn.java -o build/jvpn
"$JELF" ../../../compiladorELF/1.0.1/src/tools/CheckRules.java -o build/CheckRules
