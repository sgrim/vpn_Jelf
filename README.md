# vpn_Jelf 1.0.1

**VPN compatible con WireGuard** de la nube de jelf (el ejecutable se llama **`jvpn`**), por línea de órdenes, nativa y sin dependencias: crea la interfaz TUN, cifra por UDP y habla el mismo protocolo que el WireGuard del kernel. Sirve para las **redes privadas entre las microVM de un cliente**. **No se propone reemplazar a WireGuard**: la meta es la integración con la nube y la interoperabilidad comprobada contra el WireGuard del kernel.

**Estado: esqueleto.** Compila y pasa sus pruebas (`./test.sh`). El plan está en `PENDIENTE.md`; **los riesgos y cómo validarlos, en `RIESGOS.md`** (léalo antes de usarla: no se usa con tráfico de clientes mientras haya riesgos graves abiertos).

## Cómo

```
./build.sh   # compila con jelf (el compilador es compiladorELF) -> build/jvpn
./test.sh    # reglas del proyecto, esqueleto y registro de riesgos
```
