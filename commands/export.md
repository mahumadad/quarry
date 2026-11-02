---
name: quarry:export
description: Export findings to machine-readable formats (SARIF, JSON, CSV)
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /quarry:export — Exportar findings a formatos machine-readable

Uso: `/quarry:export [sarif|json|csv] [ruta_salida] [--all]`

## Qué hace

1. Lee el FindingsStore del engagement actual (`.pentest-state/findings.json`).
2. Por defecto exporta SOLO findings en estado VALIDATED o REPORTED —
   leads, hipótesis y findings KILLED no salen del pipeline (regla
   anti-fabricación aplicada al export).
3. `--all` incluye todo el store (útil para auditoría interna, NUNCA para
   entregar al cliente).
4. Genera el archivo vía `engine/exporters.py`:
   - **sarif** — SARIF 2.1.0 para GitHub/GitLab code scanning, Defender,
     cualquier consumidor SARIF. Incluye CVSS 4.0, EPSS, KEV en properties.
   - **json** — un objeto plano por finding, listo para crear tickets
     (Jira/Linear/ServiceNow) o alimentar automatización.
   - **csv** — triage en spreadsheet.
5. Registra el export en el custody log (`engine/custody.py`): formato,
   ruta, cantidad de findings, timestamp — el reporte attesta qué se entregó.

## Reglas

- Todo export es un evento de custody — sin excepciones.
- Un export SARIF es además un artefacto para el loop fix→retest: el cliente
  lo sube a code scanning, corrige, y `/quarry:retest` verifica.
- Los campos EPSS/KEV se enriquecen antes del export si hay findings con CVE
  (ver `references/cvss4-epss-kev.md`).
- Verificar el conteo de findings exportados contra `/quarry:findings` — un
  export de 0 findings cuando hay validados es un bug, no un resultado.

## Ejemplos

```
/quarry:export sarif outputs/eng-2026-10/findings.sarif
/quarry:export json outputs/eng-2026-10/tickets.json
/quarry:export csv outputs/eng-2026-10/triage.csv --all
```
