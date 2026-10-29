# CLI Anti-Hallucination Rules

> Fuente: PentAGI. Objetivo: evitar que el operador (humano o agente) asuma
> flags, formatos de output, o comportamiento de una herramienta que no
> verificó en esta sesión. Estas reglas son parte de `CLAUDE.md` y se
> repiten acá con el detalle completo por herramienta.

## Reglas generales

1. **`--help` antes del primer uso.** Cualquier herramienta de línea de
   comandos, antes de su primera invocación real en el engagement, se
   ejecuta con `--help` o `-h`. Los flags cambian entre versiones — no
   asumir que la sintaxis que funcionó en otro engagement sigue siendo
   válida en esta instalación.
2. **No copiar flags entre herramientas.** `-o` significa cosas distintas
   en `nmap` (no es el flag correcto, es `-oX`/`-oN`/`-oG`), `ffuf` (output
   file) y `sqlmap` (no existe igual). Verificar cada flag en su propio
   `--help`, nunca por analogía.
3. **Preferir output estructurado siempre que exista.** JSON o XML sobre
   texto libre — el texto libre invita a parsear mal o a "recordar" un
   resultado en vez de leerlo.
4. **Máximo 3 reintentos idénticos.** Si un comando falla 3 veces con la
   misma sintaxis, el problema no es transitorio — cambiar de enfoque
   (revisar conectividad, permisos, sintaxis, o escalar al operador) en
   vez de reintentar una cuarta vez esperando que funcione.
5. **Timeout default: 120 segundos por comando.** Hard limit: 20 minutos
   para cualquier proceso individual (scans largos corren en background
   con output a archivo, no bloqueando la sesión).
6. **Nunca reportar un resultado que no se vio.** Si un comando fue
   interrumpido, truncado, o el output no se leyó completo, decirlo
   explícitamente — no completar mentalmente lo que "probablemente" decía.

## Reglas por herramienta

### nmap

- Usar siempre `-oX <file>` (XML) o `-oA <basename>` (todos los formatos)
  para scans que alimentan análisis posterior. Nunca parsear solo el
  output de consola para decisiones automatizadas.
- `-sV` para version detection solo cuando el tiempo lo permite — no
  asumir versión de servicio sin banner grab confirmado.
- Scans de puertos completos (`-p-`) son lentos; usar `-p-` solo cuando el
  top-1000 (`-F`/default) ya se ejecutó y se necesita cobertura completa.

### nuclei

- Para custom, usar `NucleiRunner`: selección desde `AppProfile`, templates
  explícitos, `-jsonl`, `-dr`, `-ni`, `-duc`, límites y evidencia persistida.
- Validar sintaxis y hashes antes del run. No ejecutar directorios custom +
  community en bulk ni convertir un match en finding sin validación.
- Community se fija por versión y se revisa puntualmente. No correr
  `-update-templates` automáticamente antes de un run: una actualización no
  revisada cambia la cobertura y puede introducir requests no autorizadas.
- No filtrar `info`/`low` al evaluar cobertura; documentación y paneles son
  señales de superficie, no vulnerabilidades por defecto.

### ffuf

- `-o <file> -of json` para output estructurado.
- `-fc`/`-fs` (filter by code/size) se configuran DESPUÉS de observar al
  menos una respuesta real del target — no copiar un filtro de otro
  engagement sin verificar que aplica.
- `-mc all` en el primer pase para ver la distribución completa de códigos
  antes de filtrar.

### sqlmap

- `--batch` para no bloquear en prompts interactivos durante runs
  automatizados, pero revisar el output completo — `--batch` toma la
  opción default en cada prompt, que no siempre es la correcta para el
  caso.
- `--risk` y `--level` se suben incrementalmente, no al máximo por
  default — nivel alto genera más tráfico y más falsos positivos.
- Nunca reportar un hallazgo de sqlmap sin confirmar manualmente la
  inyección con una request propia (ver `finding-evidence-standards.md`).

### msfconsole

- Siempre `msfconsole -q -x "<comandos>; exit"` — nunca modo interactivo
  dentro de un flujo automatizado. `-q` suprime el banner, `-x` ejecuta
  comandos y `exit` cierra la sesión limpiamente.
- Verificar el módulo con `info <module>` antes de `run`/`exploit` —
  confirmar target compatibility (`show targets`) y opciones requeridas
  (`show options`) en vez de asumir defaults.

### gobuster / feroxbuster

- `-o <file>` para persistir resultados.
- Confirmar el wordlist usado y su tamaño antes de reportar "no se
  encontraron rutas adicionales" — ausencia de hallazgo con wordlist
  pequeño no es evidencia de ausencia.

### httpx / katana (recon de superficie)

- `-json` para output estructurado.
- `-silent` para logs limpios cuando se encadena con otra herramienta vía
  pipe.

### interactsh-client / Burp Collaborator (OOB)

- Verificar que el listener está activo y recibiendo (ping de prueba)
  ANTES de lanzar el payload que depende de él — un SSRF/XXE blind sin
  callback recibido no es un finding, es un intento sin resultado.

### subfinder / amass

- Combinar múltiples fuentes (`-all` en amass, o encadenar subfinder +
  amass) antes de declarar la enumeración de subdominios completa — cada
  herramienta tiene fuentes distintas y ninguna es exhaustiva sola.

## Qué hacer cuando una herramienta no está instalada o falla

1. Confirmar con `which <tool>` o `<tool> --version` antes de asumir que
   no está disponible.
2. Si falta, no improvisar una alternativa sin avisar — reportar al
   operador qué falta y qué alternativa se propone usar.
3. Nunca simular el output de una herramienta que no corrió. Si no se
   pudo ejecutar, el resultado es "no ejecutado", no un output inventado.
