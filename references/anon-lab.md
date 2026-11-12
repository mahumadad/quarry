# Anonymous Lab (Docker+Tor+VPN)

> Infraestructura de anonimato para pentests que requieren ocultamiento
> de la IP del operador. Integrada como backend `anonlab` en
> `engine/toolrunner.py`.

## Arquitectura

```
┌─────────────────────────────────────────────┐
│  Host (macOS)                               │
│                                             │
│  ┌─────────────────────────────────────┐    │
│  │  Docker network namespace (shared)  │    │
│  │                                     │    │
│  │  ┌───────────┐   ┌───────────────┐  │    │
│  │  │  torgw    │   │     kali      │  │    │
│  │  │           │   │               │  │    │
│  │  │  tor      │   │  nmap, nuclei │  │    │
│  │  │  privoxy  │   │  sqlmap, ffuf │  │    │
│  │  │  iptables │   │  hydra, etc.  │  │    │
│  │  │           │   │               │  │    │
│  │  │ :9050 SOCKS   │  ALL_PROXY →  │  │    │
│  │  │ :8118 HTTP │  │  127.0.0.1:   │  │    │
│  │  │ :5353 DNS  │  │  9050/8118    │  │    │
│  │  └─────┬─────┘   └───────────────┘  │    │
│  │        │ (solo tor uid sale)        │    │
│  └────────┼────────────────────────────┘    │
│           │                                 │
│     ┌─────▼─────┐                           │
│     │ Mullvad   │  ← conectar manualmente   │
│     │ VPN       │                           │
│     └─────┬─────┘                           │
└───────────┼─────────────────────────────────┘
            │
       ┌────▼────┐
       │ Internet│
       └─────────┘
```

Cadena completa: `kali tool → SOCKS 127.0.0.1:9050 (Tor) → host → Mullvad → internet`

## Modelo de seguridad: fail-closed

El firewall de torgw (iptables en el entrypoint) implementa:

1. **OUTPUT policy DROP** — todo tráfico saliente bloqueado por defecto.
2. **Solo tor (uid debian-tor) puede salir** — `iptables -A OUTPUT -m owner --uid-owner "$TOR_UID" -j ACCEPT`.
3. **Loopback abierto** — las tools en kali hablan con tor/privoxy en 127.0.0.1.
4. **DNS redirigido** — UDP :53 → DNSPort de Tor (:5353) como backstop.
5. **IPv6 completamente bloqueado**.

Si Tor cae o el SOCKS no responde, las tools fallan — no hay ruta alternativa
a internet. Esto es intencional: prefiere fallo a fuga.

## Cómo rutean las herramientas

### Automático (env vars)

El docker-compose y el entrypoint de kali configuran:
- `ALL_PROXY=socks5h://127.0.0.1:9050`
- `HTTP_PROXY=http://127.0.0.1:8118` (privoxy → Tor)
- `HTTPS_PROXY=http://127.0.0.1:8118`

Tools que respetan estos env vars (curl, wget, pip, httpx, subfinder)
rutean automáticamente por Tor.

### proxychains4 (`ptor` wrapper)

Para tools que no respetan env vars (nmap, y cualquier tool TCP arbitraria):

```bash
ptor nmap -sT -Pn target.com     # connect-scan vía proxychains → Tor
ptor <tool> [args]                # cualquier tool
```

`ptor` limpia los env vars de proxy antes de invocar proxychains4 (evita
doble proxy).

### `tscan` (nmap-over-Tor)

Wrapper especializado para nmap:

```bash
tscan target.com -p 80,443,8080
```

1. Resuelve el hostname por Tor (`tor-resolve`).
2. Corre `ptor nmap -sT -Pn -n <ip_resuelta> [flags]`.
3. Nunca hace DNS directo.

### `web` (whatweb/nikto con UA)

```bash
web whatweb https://target.com
web nikto -h https://target.com
```

Corre la tool con el UA de Chrome/Windows por Tor.

## User-Agent

El entrypoint configura un UA de Chrome en Windows (el más común en el
tráfico web global) en `.curlrc`, `.wgetrc` y como env var. Todas las
tools que leen estas configs lo usan automáticamente.

```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36
```

## Gestión del lab

### `anonlab.sh` (CLI completo)

```bash
./anonlab.sh up       # Conecta Mullvad, levanta Docker, verifica Tor + fail-closed
./anonlab.sh shell    # Shell interactivo en kali
./anonlab.sh status   # Muestra IP de Mullvad + IP de exit Tor
./anonlab.sh down     # Baja contenedores
```

### `up.sh` (solo Docker, sin Mullvad)

```bash
./up.sh               # Levanta torgw+kali, verifica Tor, verifica fail-closed
```

## Integración con el plugin

### Backend `anonlab` en toolrunner.py

Configurar en `.pentest-state/toolrunner.json`:

```json
{"backend": "anonlab"}
```

El runner:
1. Verifica que el contenedor `kali` está corriendo.
2. Verifica que Tor está activo (`check.torproject.org/api/ip` → `IsTor: true`).
3. Ejecuta cada comando como `docker exec kali <cmd>`.
4. Aplica las mismas reglas de timeout/retry/anti-alucinación que otros backends.
5. Reporta la IP de exit Tor en `summary()`.

### Cuándo usar

| Escenario | Backend |
|---|---|
| Pentest con IP whitelisteda, tráfico atribuible | `local` |
| Toolset pesado en Kali box dedicada | `kali` |
| Reproducibilidad con versiones pineadas | `docker` |
| **Anonimato requerido (red team, bug bounty, evasión)** | **`anonlab`** |

### Limitaciones

- **Solo TCP**: Tor no rutea UDP (excepto DNS). No hay ping, no hay UDP scan.
- **Latencia**: cada request pasa por 3+ nodos Tor. Los scans son lentos.
- **Exit node rotation**: la IP de salida cambia periódicamente. Para
  consistencia en un engagement, puede configurarse un exit node fijo en
  `torrc` (no recomendado — reduce anonimato).
- **nmap limitado a -sT**: connect scan únicamente (no SYN scan via Tor).

## Archivos fuente

```
~/Dev/personal/pentest-vm/docker/
├── docker-compose.yml    # torgw + kali, network_mode shared
├── up.sh                 # startup: Docker + Tor verify + fail-closed check
├── anonlab.sh            # CLI completo: up/shell/status/down
├── torgw/
│   ├── Dockerfile        # debian:trixie-slim + tor + privoxy + iptables
│   ├── torrc             # SocksPort 9050, DNSPort 5353, TransPort 9040
│   └── entrypoint.sh     # iptables fail-closed + privoxy + exec tor
└── kali/
    ├── Dockerfile        # kalilinux/kali-rolling + toolset completo
    └── entrypoint.sh     # proxychains4.conf + UA + PATH setup
```
