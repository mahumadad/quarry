# Anti-Fabrication Rules

> Principio rector: **PoC-or-it-didn't-happen.** Un reporte de pentest es
> una serie de claims verificables. Cada claim sin evidencia específica
> degrada la credibilidad de todo el reporte, no solo de ese finding.

## Regla 1 — No inventar findings

Un finding existe solo si fue reproducido con una acción concreta contra el
target y se observó el resultado. "Debería ser vulnerable a X porque usa
la librería Y en versión vieja" no es un finding — es una hipótesis. Pasa
a finding solo después de un intento real de explotación con resultado
observado.

## Regla 2 — No reportar vulnerabilidades solo por versión/CVE público

Detectar que un componente corre una versión con un CVE conocido es
**recon**, no un finding de explotación. Para que se convierta en finding
reportable:

- Se debe intentar el PoC público (o uno propio) contra la instancia real.
- Se debe observar el efecto esperado (crash, respuesta distinta, output
  filtrado, código ejecutado) — no asumir que porque la versión coincide,
  el exploit funciona (puede estar parchado out-of-band, tener mitigaciones
  de WAF, o el CVE puede requerir una configuración que este target no
  tiene).
- Si no se pudo intentar el PoC (por riesgo, scope, o tiempo), se reporta
  como **Observación de versión desactualizada** (severidad informativa/
  baja según exposición), no como el finding del CVE con su severidad
  original.

## Regla 3 — No asumir impacto sin demostración

"Podría permitir tomar control total del servidor" sin haber ejecutado un
comando real es una hipótesis. El campo **Impact (Demonstrated)** de
`finding-template.md` solo documenta lo que efectivamente se vio: el
comando que corrió, el archivo que se leyó, el dato que se extrajo. Si la
cadena de impacto continúa más allá de lo demostrado, esa continuación se
documenta aparte como hipótesis abierta — nunca se mezcla con lo demostrado
en el mismo campo.

## Regla 4 — Evidence tags obligatorios

Todo finding y todo claim dentro de un finding lleva una etiqueta:

| Tag | Significa | Qué habilita |
|---|---|---|
| **Demonstrated** | Hay PoC funcional reproducible con request/response o output de herramienta que muestra el efecto completo | Se reporta con su severidad completa |
| **Inferred** | Hay evidencia parcial consistente con la vulnerabilidad, pero no un PoC end-to-end (ej. timing side-channel, error diferencial, comportamiento anómalo sin confirmación de la causa exacta) | Se reporta con severidad ajustada a la baja y la limitación explícita en el texto |
| **Unproven** | Es una hipótesis razonable sin evidencia que la respalde todavía | No se reporta como finding — va en Gaps/observaciones del engagement report como pista para trabajo futuro |

Un finding puede combinar tags en distintas partes: el acceso inicial
`Demonstrated` y el impacto final de una chain `Inferred` si el último
salto no se ejecutó por estar fuera de las reglas de engagement (ej. no se
ejecutó la escritura destructiva en prod aunque el control de acceso roto
sí se demostró).

## Regla 5 — No impacto teórico

Evitar lenguaje como "un atacante sofisticado podría eventualmente...".
Si el impacto requiere condiciones no verificadas (acceso a otro sistema,
timing específico, ingeniería social adicional), decirlo explícitamente
como precondición no verificada, no como parte del impacto confirmado.

## Regla 6 — Cada claim cita su evidencia específica

No basta con que el finding tenga una sección de evidencia general — cada
afirmación relevante dentro de la descripción y el impacto debe poder
trazarse a una línea del request/response o un output específico. Si al
escribir una frase no se puede señalar qué evidencia la sostiene, la frase
se reescribe o se elimina.

## Regla 7 — No duplicar ni inflar

- Un mismo root cause que se manifiesta en múltiples endpoints se reporta
  como un finding con múltiples instancias listadas, no como N findings
  separados (salvo que el engagement/cliente requiera reporte por
  endpoint para tracking).
- No contar el mismo finding dos veces en una chain y en el listado
  individual con severidades distintas sin justificar la diferencia.

## Regla 8 — Validación adversarial antes de reportar

Todo finding pasa por el loop generador↔checker (`engine/rebuttal.py`):
un segundo rol, sin el contexto de quien lo escribió, intenta refutarlo.
Outcomes posibles: `ACCEPTED`, `STALL` (falta evidencia — se completa antes
de reintentar), `KILLED` (no sobrevive el escrutinio — no se reporta).
Máximo 3 rondas por finding; si tras 3 rondas sigue en `STALL`, se degrada
a `Unproven` y pasa a Gaps.

## Señales de que un finding está fabricado o inflado (red flags)

- El campo Evidence tiene un response genérico que no corresponde
  exactamente al request mostrado.
- El impacto usa condicional ("podría", "permitiría", "eventualmente") en
  vez de pasado demostrado ("se extrajo", "se ejecutó", "se leyó").
- No hay timestamp verificable de cuándo se ejecutó la prueba.
- Los steps to reproduce no son suficientes para que un tercero independiente
  llegue al mismo resultado.
- La severidad CVSS no tiene justificación métrica por métrica.
