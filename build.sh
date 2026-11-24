#!/bin/sh
# Compila con jelf -> build/. El compilador es el de ../../../compiladorELF/1.0.1/src; JELF=/otra/ruta/jelf.sh lo cambia.
set -e
cd "$(dirname "$0")"
JELF="${JELF:-../../../compiladorELF/1.0.1/src/jelf.sh}"
[ -f ../../../compiladorELF/1.0.1/src/jelf-1.0.1.jar ] || (cd ../../../compiladorELF/1.0.1/src && ./build.sh > /dev/null)
mkdir -p build
EDGE=../../../edge_Jelf/1.0.1/src/crypto # la criptografía de edge_Jelf: se compila junto, no se copia
EDGEFILES="$EDGE/Blake2s.java $EDGE/ChaCha20.java $EDGE/Poly1305.java $EDGE/ChaCha20Poly1305.java $EDGE/Fe.java $EDGE/FeMul.java $EDGE/X25519.java"
"$JELF" vpn/Jvpn.java vpn/VpnTest.java vpn/Wg.java vpn/Handshake.java vpn/Session.java vpn/B64.java vpn/Ip.java vpn/Rand.java vpn/Tunnel.java $EDGEFILES -o build/jvpn
"$JELF" ../../../compiladorELF/1.0.1/src/tools/CheckRules.java -o build/CheckRules
