# /pt:retest — Engagement de verificación de remediación

Uso: `/pt:retest <engagement_original_dir>`

## Qué hace

Lanza el workflow `retest.yaml` contra los findings de un engagement
previo: el cliente aplicó fixes y hay que probar que los exploits murieron.

## Flujo

1. **Carga el engagement original**: findings, PoCs (steps-to-reproduce),
   snapshot del target (engine/checkpoint.py / target_diff).
2. **Baseline diff** (`engine/target_diff.py`): qué cambió en el target
   desde el scan original. Cambios inesperados (rutas nuevas, servicios
   nuevos) se reportan al operador ANTES de re-testear — pueden ser scope
   nuevo no autorizado.
3. **Re-exploit en sesión fría** por cada finding (agente re-exploit-agent):
   - cookie jar nuevo, credenciales frescas del vault,
   - ejecutar el PoC EXACTO del reporte,
   - clasificar: FIXED / PARTIAL / NOT_FIXED / REGRESSED (ver retest.yaml).
4. **Variant sweep**: para findings cuyo patrón tenía siblings
   (variant-analysis), re-barrer las ubicaciones no reportadas — el fix de
   instancia sin fix de patrón es el caso más común de "fix" falso.
5. **Reporte de retest**: tabla finding × estado × evidencia nueva. Sin
   hunting nuevo — superficie nueva requiere engagement nuevo con su scope.

## Reglas

- Todo re-test es evidencia nueva: requests/responses del re-test se guardan
  con timestamp y hash como cualquier evidencia (custody log).
- PARTIAL y NOT_FIXED reabren el finding con la evidencia del re-test —
  nunca "el cliente dijo que lo arregló" como cierre.
- FIXED también exige evidencia: captura del control nuevo funcionando
  (el 403, la validación), no solo "ya no funciona el payload".
- Si el target cambió estructuralmente (versión mayor, rewrite), declararlo:
  un retest sobre una app distinta a la auditada tiene validez limitada —
  recomendar engagement nuevo.

## Ejemplo

```
/pt:retest engagements/acme-2026-09
```
