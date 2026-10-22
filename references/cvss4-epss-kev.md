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
