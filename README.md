# vpn_Jelf 1.0.1

**VPN compatible con WireGuard** de la nube de jelf (el ejecutable se llama **`jvpn`**), por línea de órdenes, nativa y sin dependencias: crea la interfaz TUN, cifra por UDP y habla el mismo protocolo que el WireGuard del kernel. Sirve para las **redes privadas entre las microVM de un cliente**. **No se propone reemplazar a WireGuard**: la meta es la integración con la nube y la interoperabilidad comprobada contra el WireGuard del kernel.

**Estado: V0 (el protocolo).** Interopera con el WireGuard del kernel en los dos sentidos (`AUDITORIA.md` 2); todavía NO crea la interfaz TUN ni enruta tráfico (V1). Compila y pasa sus pruebas (`./test.sh`, que incluye el comparador del kernel con docker). El plan está en `PENDIENTE.md`; **los riesgos y cómo validarlos, en `RIESGOS.md`** (léalo antes de usarla: no se usa con tráfico de clientes mientras haya riesgos graves abiertos).

## Cómo

```
./build.sh   # compila con jelf (el compilador es compiladorELF) -> build/jvpn
./test.sh    # reglas, pruebas propias del protocolo (14) y la prueba contra el WireGuard del kernel (docker; tools/wg_oracle.sh)
jvpn genkey > k; jvpn pubkey k          # claves como «wg genkey» y «wg pubkey»
```
