# vpn_Jelf 1.0.1

VPN compatible con WireGuard de la nube de jelf (ejecutable `jvpn`), por línea de órdenes, nativa y sin dependencias.

Software propietario (ver `LICENSE`). Repositorio: https://github.com/sgrim/vpn_Jelf.git. Lo que falta, priorizado, está en `PENDIENTE.md`; las decisiones y las mediciones en `AUDITORIA.md`; **los riesgos y cómo se validan, en `RIESGOS.md`**. Este fichero es solo lo operativo.

## Lo propio de este proyecto

- **Riesgos primero:** antes de dar una fase por terminada se mira `RIESGOS.md`: cada riesgo de gravedad alta lleva su prueba (interoperabilidad con el WireGuard del kernel, mensajes hostiles, medición de tiempos, aislamiento entre inquilinos, revisión). Un riesgo se cierra solo con evidencia escrita en `AUDITORIA.md`. No se usa con tráfico de clientes mientras haya riesgos graves abiertos.
- **Solo el protocolo de WireGuard, sin variantes propias:** Noise_IKpsk2 con Curve25519, ChaCha20-Poly1305, BLAKE2s y HKDF. La criptografía vive en `edge_Jelf` y se compara con la JVM y OpenSSL; aquí solo se usa.
- **Privilegios mínimos:** el proceso abre TUN y el socket con el privilegio y lo suelta ANTES de leer un paquete; el archivo de configuración con claves debe tener permisos 0600.
- **Las cifras de velocidad se miden contra el WireGuard del kernel y se rotulan** (WSL2 anidado hoy); nada de prometer lo que no se midió.
- **Los secretos** (claves privadas, precompartidas, de sesión) viven en arreglos reutilizables puestos en cero al terminar; nunca en `String` ni en los registros.

## Reglas del proyecto (no negociables)

- **Identificadores en inglés** (paquetes, clases, métodos, variables, constantes, opciones de la línea de comandos, campos de las API). **Comentarios, documentación y mensajes al usuario en español**, con todas sus tildes.
- **Alta eficiencia y bajo consumo de memoria.** Sin reservas de memoria en el camino caliente (arreglos y estructuras propias sobre `byte[]`/`long[]` en lugar de objetos), sin copias que se puedan evitar. Todo cambio de rendimiento se mide (antes y después, mediana de varias series) y se rotula con su entorno; una cifra sin medir es un objetivo, y se escribe como tal.
- **Seguridad desde el diseño.** Toda entrada externa se valida en la frontera (largos, rangos, formato) antes de usarla; mínimo privilegio; nada de secretos en los registros ni en el repositorio; los secretos se comparan sin cortar en el primer byte distinto; cada defensa se prueba con su caso hostil.
- **Una sola pasada, con ventana deslizante y máquinas de estados (el esquema de `Pia` en Duniti, `D:\virtualNetbeans\winxp\projectEclipse\source_Duniti\2.3.1\src\fago\web\compiler\Pia.java`).** Lo que se lee (código, SQL, mensajes, configuración) se procesa **leyéndolo una vez**, en bloques sobre un búfer fijo que se rellena cuando se vacía (así los límites de los bloques no se notan, y vale igual para un archivo que para un socket); se recorre **byte a byte**; los últimos bytes viven en una **ventana deslizante** de variables locales (`b`, `b0`, `b1`, `b2`... que se desplazan en cada byte; no se vuelve a mirar el búfer hacia atrás), y con ella se reconocen los operadores y marcas de varios bytes; **una variable de estado** decide cada transición (dentro de una cadena, de un comentario, de un identificador, de un número...); el token en curso se acumula en un búfer reutilizable (sin crear un `String` por token); lo anidado va en pilas explícitas. No hay lista de tokens ni un segundo recorrido. Si una regla del lenguaje o del protocolo exigiera mirar más lejos de lo ya leído, se define una regla propia comprobable con lo ya leído y se documenta (puede ser más estricta).
- **Se usan las clases de `com.util.put`** (`D:\virtualNetbeans\winxp\projectEclipse\compiladorELF\1.0.1\src\com\util\put`: `ByteVector`, `IntMap`, `IntStack`, `MapBytes`, `ObjStack`, `ObjVector`) en lugar de escribir otras: `MapBytes` para tablas de palabras clave y nombres, `IntStack`/`ObjStack` para los estados y los ámbitos anidados, `ByteVector` para acumular tokens y salidas, `IntMap` y `ObjVector` para los índices y las listas. `build.sh` las compila junto al proyecto desde el repositorio del compilador (no se copian). Si falta algo de uso general, se añade ahí y lo usan todos los proyectos.
- **Sin recursión** sobre datos anidados: pilas explícitas sobre arreglos (el esquema «apilar trabajo; mientras quede algo, sacar y procesar»).
- **Sin `java.util` ni dependencias**: las estructuras son las de `com.util.put` (ver abajo) o propias, sobre `byte[]`.
- **Las herramientas se escriben en este mismo Java, compiladas por jelf**: ni Python ni otro lenguaje; los lanzadores son scripts de shell finos.
- **Los fuentes llevan la cabecera de copyright** (el bloque de Duniti: cópiese de otro `.java` del proyecto) antes de la descripción del archivo; `tools/CheckRules.java` del compilador lo vigila y `test.sh` lo corre.
- **Codificación de los fuentes (regla fija): todo archivo de texto que cree la IA (`.java`, `.md`, `.sh`, `.bat`, `.c`, `.txt`...) se crea y se guarda en UTF-8, sin BOM, SALVO QUE EL USUARIO ACLARE OTRA COSA para ese archivo** (comentarios y mensajes en español con sus tildes; la `©` de la cabecera). Nunca Latin-1 / ISO-8859-1 / Windows-1252 ni UTF-16, y **nunca texto doblemente codificado** (los bytes `C3 83 C2 A9` en lugar de `C3 A9` de una «é», o el carácter U+FFFD). No se convierte a otra codificación: `javac -encoding UTF-8`; jelf lee los bytes tal cual. **Al crear un archivo con un editor, un `heredoc` o una herramienta, comprobarlo:** la regla `utf8` de `tools/CheckRules.java` del compilador, que corre sobre todos esos archivos (UTF-8 válido, sin BOM, sin sobrelargas ni sustitutos, sin mojibake ni U+FFFD) lo vigila y `test.sh` la corre. Un archivo que falla se vuelve a escribir en UTF-8; no se «arregla» a mano el texto roto.
- **Una prueba se valida con una mutación**: se rompe a propósito el código y se comprueba que la prueba lo detecta. Una prueba que no puede fallar no vale.
- **Las cifras llevan su entorno** (hoy WSL2 anidado, kernel 5.10.102.1; ningún dato es de un Linux real ni de hardware RISC-V real hasta que se repita allí).
- Un paso se da por terminado con `./test.sh` en verde, y se commitea (mensaje en español) y se sube al repositorio.

## Cómo se compila y se prueba

```
./build.sh      # compila con jelf -> build/
./test.sh       # compila, vigila las reglas (cabecera, UTF-8, sin java.util, identificadores en inglés) y prueba
```

El compilador es el de `../../../compiladorELF/1.0.1/src` (jelf); `JELF=/otra/ruta/jelf.sh ./build.sh` lo cambia. Los comparadores y emuladores externos (Docker, qemu, `gcc`) son el objeto de una medida, no parte del proyecto.
