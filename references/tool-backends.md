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

## Backend `kali` (Kali remoto vía REST)

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
# Dockerfile base sugerido (construir y taggear pentest-plugin/toolkit:1.0):
FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap masscan sqlmap nuclei ffuf gobuster curl dnsutils whois \
    metasploit-framework seclists wordlists \
 && rm -rf /var/lib/apt/lists/*
```

Configuración: `{"backend": "docker", "docker_image": "pentest-plugin/toolkit:1.0"}`.
El runner envuelve cada comando en `docker run --rm --network host {image}`.
Montar el directorio del engagement como volumen si las herramientas deben
escribir outputs: extender `_run_local` según necesidad.

## Reglas transversales

- El backend se declara al inicio del engagement y queda en el custody log.
- Cambiar de backend a mitad de engagement es un evento de custody (nota) —
  afecta reproducibilidad de la evidencia.
- Ningún backend ejecuta nada fuera de scope: `guard.py` valida targets
  contra `engine/scope.py` antes de cualquier ejecución.
