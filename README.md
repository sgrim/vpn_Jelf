# vpn_Jelf 1.0.1

**VPN compatible con WireGuard** de la nube de jelf (el ejecutable se llama **`jvpn`**), por línea de órdenes, nativa y sin dependencias: crea la interfaz TUN, cifra por UDP y habla el mismo protocolo que el WireGuard del kernel. Sirve para las **redes privadas entre las microVM de un cliente**. **No se propone reemplazar a WireGuard**: la meta es la integración con la nube y la interoperabilidad comprobada contra el WireGuard del kernel.

**Estado: V1 (túnel de un par por TUN, sin privilegios).** Interopera con el WireGuard del kernel en los dos sentidos (`AUDITORIA.md` 2); `jvpn up` crea la TUN, suelta los privilegios y reenvía tráfico real de un par (`AUDITORIA.md` 3); faltan varios pares, rutas, DNS e IPv6. Compila y pasa sus pruebas (`./test.sh`, que incluye el comparador del kernel con docker). El plan está en `PENDIENTE.md`; **los riesgos y cómo validarlos, en `RIESGOS.md`** (léalo antes de usarla: no se usa con tráfico de clientes mientras haya riesgos graves abiertos).

## Cómo

```
./build.sh   # compila con jelf (el compilador es compiladorELF) -> build/jvpn
./test.sh    # reglas, pruebas propias del protocolo (14) y la prueba contra el WireGuard del kernel (docker; tools/wg_oracle.sh) y la de tráfico real por la TUN (tools/tun_oracle.sh)
jvpn genkey > k; jvpn pubkey k          # claves como «wg genkey» y «wg pubkey»
```
