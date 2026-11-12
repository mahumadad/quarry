# CVSS 4.0 + EPSS + CISA KEV — Scoring Guidance

> Estándar de scoring del plugin. CVSS 4.0 es el vector primario; EPSS y KEV
> modulan PRIORIDAD (no severidad). Esta referencia define cómo se combinan.

## CVSS 4.0 (vector primario)

Formato: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`

Diferencias clave vs 3.1 que afectan cómo puntuamos:

| Métrica | Qué cambió | Regla del plugin |
|---------|-----------|------------------|
| AT (Attack Requirements) | Nueva: condiciones fuera del control del atacante (race windows, configuración específica) | AT:P solo si se DEMOSTRÓ que la condición existe (ej. race confirmada); no asumirla |
| UI (User Interaction) | N (none) / P (passive: la víctima navega) / A (active: acción específica) | XSS reflejado con click en link = UI:A típicamente; stored que dispara solo = UI:P |
| VC/VI/VA vs SC/SI/SA | Impacto separado en sistema Vulnerable vs Subsequent | Un SSRF→IMDS que compromete la cuenta cloud: VC alto en la app, SC/SI en subsequent — justificar cada uno con lo demostrado |
| Métricas de amenaza (E) | E:A (attacked/POC) modula el score | E:A cuando hay exploit público o PoC demostrado en el engagement |
| Métricas ambientales | Por instancia del cliente | Usar solo si el cliente define requisitos CIA de sus activos |

Compatibilidad: si el cliente/plataforma exige CVSS 3.1 (HackerOne lo acepta
en ambos), incluir ambos vectores en el finding; el 4.0 manda internamente.
Justificación por métrica sigue siendo obligatoria (finding-template.md) —
cada métrica trazada a lo observado, no a lo teórico.

## EPSS (Exploit Prediction Scoring System)

Probabilidad (0–1) de explotación en los próximos 30 días, por CVE.

- Fuentes: API `https://api.first.org/data/v1/epss?cve=CVE-XXXX-YYYY` o
  bulk download diario de FIRST.
- Uso: SOLO para findings basados en CVE (supply-chain, CVE-testing).
  Un finding de lógica propia no tiene EPSS.
- Interpretación: percentil > score absoluto. EPSS ≥ 0.1 (top ~5%) ya es
  señal fuerte; ≥ 0.5 es prioridad inmediata.
- Registrar en finding metadata: `epss_score`, `epss_percentile`, fecha de
  consulta (EPSS cambia diario).

## CISA KEV (Known Exploited Vulnerabilities)

Catálogo de CVEs con explotación confirmada en el mundo real.

- Fuente: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Uso: si un CVE del engagement está en KEV, el finding lleva
  `cisa_kev: true` y la prioridad de remediación sube a inmediata
  independientemente del CVSS — hay actores usándolo activamente, incluye
  fecha de due-date de CISA para agencias (útil como presión de negocio).

## Composición de prioridad (para el reporte)

Severidad (CVSS 4.0) ≠ Prioridad de remediación. El reporte ordena por:

```
prioridad = f(severidad, exposición real del asset, EPSS/KEV si aplica,
              facilidad de exploit demostrada, chain membership)

Ejemplos:
- CVSS 9.8 + EPSS 0.001 + asset interno       → alta pero no urgente
- CVSS 6.5 + KEV + internet-facing            → URGENTE (explotación activa)
- CVSS 5.4 standalone vs mismo bug en chain   → la chain sube prioridad
    que llega a crown jewels (ver chain_engine capability graph)
```

Reglas:
- NUNCA inflar CVSS para compensar EPSS bajo — son ejes distintos y el
  reporte los muestra separados.
- Un finding Demonstrated siempre supera en prioridad a uno Inferred de
  igual score (evidencia > teoría).
- Los gates de severidad por modo (findings.py HUNT_MODE_SEVERITY_GATES)
  se aplican sobre CVSS; EPSS/KEV no mueven el gate, mueven el orden.

## CVE Triage Tiers (fire / smoke / ice)

Metodología de priorización rápida para CVEs en inventario, complementaria
a CVSS+EPSS+KEV. Basada en el modelo de CVEngine: cada CVE se clasifica en
un tier según señales de explotabilidad, y el tier determina la acción.

### Definición de tiers

| Tier | Criterio (cualquier condición basta) | Acción |
|------|--------------------------------------|--------|
| **Fire** | CVE en CISA KEV; O exploit público verificado (módulo Metasploit, PoC funcional en ExploitDB); O EPSS > 0.7 | Inmediata: validar en el target, reportar como prioridad P1 |
| **Smoke** | CVSS ≥ 7.0 + EPSS > 0.1; O PoC no verificado (advisory sin PoC público reproducible); O listado en ENISA EUVD como explotado; O match exacto producto+versión en el inventario | Investigar pronto: confirmar afectación, intentar PoC, reportar si se confirma |
| **Ice** | CVSS < 7.0, EPSS < 0.1, sin exploit conocido, sin evidencia de explotación activa | Backlog: registrar, monitorear, re-evaluar si aparecen señales nuevas |

### Fuentes de datos por tier

| Fuente | Fire | Smoke | Ice |
|--------|------|-------|-----|
| CISA KEV | ✓ (presencia = Fire) | — | — |
| ENISA EUVD | — | ✓ (explotado = Smoke) | — |
| Metasploit modules | ✓ (módulo funcional) | — | — |
| ExploitDB | ✓ (PoC verificado) | ✓ (PoC sin verificar) | — |
| VulnCheck KEV | ✓ (equivalente a CISA KEV) | — | — |
| EPSS | ✓ (> 0.7) | ✓ (> 0.1 + CVSS ≥ 7) | referencia |
| CVSS 4.0 | referencia | ✓ (≥ 7.0 + EPSS) | referencia |

### Mapeo a severidad del plugin

El tier no reemplaza CVSS — modula la prioridad de acción:

| Tier | Efecto en prioridad |
|------|-------------------|
| Fire | Finding sube a P1 independientemente del CVSS. Si CVSS < 7.0 pero está en KEV, la prioridad de remediación sigue siendo urgente (explotación activa > score teórico) |
| Smoke | Finding se investiga en la fase actual. Si se confirma explotabilidad, escala a Fire |
| Ice | Se reporta como informativo o medium según CVSS. Puede escalar si durante el engagement se descubre un vector de explotación |

### Backport awareness

Muchas distribuciones parchean CVEs sin cambiar el número de versión del
paquete upstream. Un match de versión NO es prueba de vulnerabilidad:

- **OSV** (osv.dev): base de datos unificada de vulnerabilidades por
  ecosistema con rangos de versiones afectadas por distro.
- **Debian Security Tracker** (security-tracker.debian.org): estado de
  parche por paquete Debian/Ubuntu, con versión fija por release.
- **Red Hat CVE Database**: similar para RHEL/CentOS/Fedora.

Regla: si el target corre una distro que backportea, verificar contra el
tracker de la distro antes de clasificar como vulnerable. Un finding
basado solo en banner/versión sin verificación de backport se queda en
**Inferred**, no Demonstrated.

### Ejemplo de clasificación

CVE-2024-21762 (Fortinet FortiOS — out-of-bounds write, pre-auth RCE):

```
CVSS 4.0:  9.8 (AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)
EPSS:      0.91 (percentil 99)
CISA KEV:  sí (fecha: 2024-02-09)
Metasploit: módulo disponible
ExploitDB:  PoC verificado

→ Tier: FIRE (3 señales independientes)
→ Prioridad: P1 — validar inmediatamente contra el inventario FortiOS
→ Si producto+versión match y no hay backport: Demonstrated tras PoC exitoso
```

CVE-2024-3400 (Palo Alto PAN-OS — command injection, pre-auth):

```
CVSS 4.0:  10.0
EPSS:      0.95
CISA KEV:  sí
Metasploit: no (al momento de evaluación)
ExploitDB:  PoC público funcional

→ Tier: FIRE
→ Prioridad: P1
```

CVE hipotético en librería interna, CVSS 5.3, EPSS 0.02, sin KEV,
sin PoC público:

```
→ Tier: ICE
→ Prioridad: backlog, registrar en inventario, re-evaluar mensualmente
```
