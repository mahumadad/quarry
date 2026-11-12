# Triage Brocards — referencia rápida

> Versión de referencia de `skills/validate/triage-brocards`. El skill manda;
> este documento existe para consulta rápida del operador y para citar en
> reportes ("descartado según B3 del protocolo de triage").

| # | Brocard | Decisión típica |
|---|---------|-----------------|
| B1 | Sin trigger concreto no hay finding — el input exacto es el requisito de entrada | INFO-NEEDED → DISMISS |
| B2 | Versión detectada ≠ vulnerabilidad explotable (backports, builds) | INFO-NEEDED (trigger vivo o reachability) |
| B3 | El scanner es testigo, no juez — toda salida de herramienta requiere una reproducción manual | DISMISS si no se reproduce |
| B4 | El impacto debe nombrar víctima y asset concretos del asset-map | DISMISS si el asset es imaginario/fuera de scope |
| B5 | By-design no es bug standalone — pero se archiva como material de chain | DISMISS + archivar en brain |
| B6 | Una observación, un claim — los bundles se dividen antes de triage | SPLIT |
| B7 | ¿Duplicado o derivado? — dedup y never-submit antes de gastar budget | MERGE / DISMISS |

## Reglas de uso

- Aplicar en orden; el primer brocard decisivo gana.
- Toda decisión queda registrada con número de brocard y razón de una línea.
- INFO-NEEDED tiene UN ciclo de seguimiento; sin respuesta → DISMISS y la
  pregunta abierta pasa a los gaps de cobertura del reporte.
- Los descartes por B5 se revisan en la fase de chaining como candidatos a
  eslabones.
- Los brocards ordenan la cola; NO reemplazan el validation gate ni los
  evidence standards para lo que se reporta.
