# Tool Execution Backends

> Configuración de `engine/toolrunner.py`. Define DÓNDE corren las
> herramientas del engagement para que sea reproducible y declarado, en vez
> de depender de lo que haya en el $PATH local.

## Backend `local` (default)

Herramientas instaladas en la máquina del operador. El runner:
- verifica disponibilidad con `which` (cacheado por engagement),
- corre `{tool} --help` antes del primer uso (regla CLI anti-alucinación,
  aplicada mecánicamente),
- aplica timeout 120s / hard limit 20min / máx 3 reintentos idénticos.

Sin configuración necesaria. Ideal para web/API testing con curl, ffuf,
nuclei, sqlmap instalados localmente.

## Backend `kali` (Kali remoto vía REST) — EXPERIMENTAL

Para tooling pesado (nmap masivo, Metasploit, herramientas que no corren en
macOS del operador) en una Kali box dedicada.

1. Desplegar un servidor estilo MCP-Kali-Server en la Kali:
   - contrato esperado: `GET /health` → `{"status":"ok"}`;
     `POST /api/command` con body `{"command": "...", "timeout": N}` →
     `{"stdout": ..., "stderr": ..., "return_code": N}`.
2. Configurar en el engagement:
   ```bash
   python3 engine/toolrunner.py  # o editar .pentest-state/toolrunner.json:
   {"backend": "kali", "kali_url": "http://kali-box:5000"}
   ```
3. El runner chequea `/health` una vez; si no responde, `is_available()`
   retorna False y las skills deben caer a fallback local.

Notas:
- La Kali box queda como infraestructura del engagement: registrarla en el
  scope (su IP origina el tráfico ofensivo).
- `msfconsole` sigue la regla CLAUDE.md: `-q -x "...; exit"`, nunca interactivo.
- Todo comando pasa igual por `engine/guard.py` (PreToolUse hook) antes de
  salir — el backend remoto no es bypass del guard.

## Backend `docker`

Imagen pineada con versiones declaradas de herramientas — máxima
reproducibilidad entre operadores y entre runs del benchmark.

```bash
# Dockerfile base sugerido (construir y taggear quarry/toolkit:1.0):
FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap masscan sqlmap nuclei ffuf gobuster curl dnsutils whois \
    metasploit-framework seclists wordlists \
 && rm -rf /var/lib/apt/lists/*
```

Configuración: `{"backend": "docker", "docker_image": "quarry/toolkit:1.0"}`.
El runner envuelve cada comando en `docker run --rm --network host {image}`.
Montar el directorio del engagement como volumen si las herramientas deben
escribir outputs: extender `_run_local` según necesidad.

## Backend `anonlab` (Docker+Tor anonymous lab) — EXPERIMENTAL

Para engagements que requieren anonimato del operador: red team con
evasión, bug bounty donde no se quiere exponer la IP, o targets que
bloquean rangos residenciales/cloud. El tráfico fluye:

```
kali container → SOCKS Tor (torgw) → host → Mullvad VPN → internet
```

### Arquitectura

Dos contenedores Docker con network namespace compartido:

- **torgw**: gateway Tor con iptables fail-closed — solo el proceso `tor`
  puede salir directo; cualquier otro tráfico es rechazado (sin fuga).
  Corre Tor (SocksPort 9050) + privoxy (HTTP proxy 8118 → Tor).
- **kali**: toolset completo (nmap, nuclei, sqlmap, ffuf, hydra, etc.)
  en `network_mode: service:torgw`. Todo su tráfico pasa por el netns de
  torgw y sale por Tor.

Ver `references/anon-lab.md` para el detalle completo de la arquitectura.

### Setup

1. Levantar el lab: `cd ~/Dev/personal/pentest-vm/docker && ./anonlab.sh up`
   (o `./up.sh` para solo Docker sin Mullvad).
2. Verificar: el script comprueba automáticamente `IsTor: true` y
   fail-closed (curl directo debe fallar).
3. Configurar el engagement:
   ```json
   {"backend": "anonlab", "anonlab_container": "kali"}
   ```

### Cómo rutean las herramientas

| Herramienta | Ruta |
|---|---|
| curl, wget, pip, httpx | Env vars `ALL_PROXY` / `HTTP_PROXY` (auto) |
| nmap | `tscan <host>` o `ptor nmap -sT -Pn <target>` |
| nuclei, subfinder, katana | `HTTP_PROXY` (auto) o `ptor` si falla |
| sqlmap, ffuf, gobuster | `--proxy socks5h://127.0.0.1:9050` o env vars |
| cualquier otro TCP | `ptor <tool> [args]` (proxychains4 wrapper) |

### Notas

- `tscan` resuelve DNS por Tor antes del scan — nunca DNS directo.
- El UA por defecto es Chrome/Windows (mezclarse en el tráfico).
- Los outputs se guardan en `/loot` dentro del contenedor (volumen montado
  en `~/Dev/personal/pentest-vm/docker/../loot`).
- Mullvad VPN es la capa externa (conectar manualmente antes de `anonlab up`).
- El runner verifica Tor activo con `check.torproject.org/api/ip` antes
  de aceptar el backend como disponible.

## Maturity levels

| Backend   | Status       | Policy shared | Tests |
|-----------|-------------|---------------|-------|
| `local`   | Stable      | Yes           | Yes   |
| `docker`  | Stable      | Yes           | Yes   |
| `kali`    | Experimental| Yes           | No    |
| `anonlab` | Experimental| Yes           | No    |

Experimental backends share the policy engine (`command_policy()` runs
before every execution regardless of backend) and custody logging, but
lack dedicated test coverage. Use them in engagements where their
capabilities are needed, but be aware they are less battle-tested.

## Reglas transversales

- El backend se declara al inicio del engagement y queda en el custody log.
- Cambiar de backend a mitad de engagement es un evento de custody (nota) —
  afecta reproducibilidad de la evidencia.
- Ningún backend ejecuta nada fuera de scope: `guard.py` valida targets
  contra `engine/scope.py` antes de cualquier ejecución.

## Capacidades y wordlists reproducibles

`engine/tool_registry.py` mantiene una lista curada de capacidades y fallbacks, no un instalador
ni una colección indiscriminada de herramientas. `ToolRegistry.select("web-crawl")` elige el primer
backend disponible en orden declarado y registra versión/backend; `snapshot()` deja gaps explícitos
para doctor y cobertura. La ejecución sigue pasando por `ToolRunner`, policy y artefactos.

`engine/wordlists.py` indexa únicamente listas locales indicadas por el operador. Antes de usar una,
`scan([...])` guarda hash/tamaño/fecha/tags y `select(...)` persiste criterios y elección por run/task.
Si no hay lista compatible, el resultado es un gap; no se sustituye silenciosamente por otra lista ni
se afirma que no existen rutas. Las listas de terceros no se descargan ni ejecutan automáticamente.
