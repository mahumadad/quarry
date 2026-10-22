# Benchmark Harness — medición objetiva del plugin

> Propósito: saber si el plugin MEJORA con cada cambio. Sin benchmark, cada
> edición de skills es una fe. Con benchmark, es un número: recall sobre
> targets conocidos, falsos positivos, y costo.

## Cómo funciona

1. `targets/*.yaml` — apps deliberadamente vulnerables con la lista de
   findings esperados (ground truth curada a mano).
2. Se corre un engagement del plugin contra el target (local, Docker).
3. `score.py` compara `.pentest-state/findings.json` del run contra el
   ground truth del target y produce:
   - **recall** — fracción de findings esperados encontrados (por severidad),
   - **precision** — fracción de findings reportados que son reales
     (no duplicados, no falsos, no never-submit),
   - **costo** — tool calls / tokens del run (engine/budget + cost_estimator),
   - **custodia** — % de findings con evidencia hash íntegra.

## Uso

```bash
# 1. Levantar el target (ejemplo Juice Shop):
docker run -d --name bench-juice -p 3000:3000 bkimminich/juice-shop

# 2. Correr el engagement contra http://localhost:3000 con el workflow
#    web-app-pentest (operador o agente, según se quiera medir).

# 3. Puntuar el run:
python3 benchmarks/score.py \
  --target benchmarks/targets/juice-shop.yaml \
  --findings /path/al/engagement/.pentest-state/findings.json \
  --out benchmarks/results/$(date +%F)-juice.json
```

## Reglas del harness

- **Máquina de estados limpia**: reiniciar el contenedor entre runs — apps
  con estado (Juice Shop persiste retos resueltos) contaminan la medición.
- **Misma semilla de comparación**: el ground truth NO se edita para que un
  run pase; si el plugin encuentra algo real que falta en el YAML, se audita
  y se agrega como expected nuevo con justificación (commit aparte).
- **Regression gate en CI**: `.github/workflows/validate.yml` corre la
  validación estructural siempre; el benchmark completo corre on-demand
  (necesita Docker + tiempo) pero `score.py` sobre results/ históricos
  detecta caídas de recall entre versiones.
- **Resultados en `results/`** con fecha + commit SHA del plugin — la curva
  de recall en el tiempo es el KPI del proyecto.

## Targets iniciales

| Target | Tipo | Expected findings | Por qué |
|--------|------|-------------------|---------|
| juice-shop | web moderna (SPA+API) | ~20 curados | OWASP flagship, cobre XSS/SQLi/IDOR/JWT/business-logic |
| crapi | API-first | ~10 | BOLA/IDOR/JWT/rate-limit en API pura |
| dvwa | clásico PHP | ~8 | clases básicas, rápido de correr |

## Extensión

Agregar un target = nuevo YAML en `targets/` con ground truth curada. Buenas
fuentes de ground truth: los writeups oficiales de cada app, los retos
documentados, y corridas manuales auditadas. WebGoat y
vulnerable-apps de GraphQL (DVGA) son candidatos naturales siguientes.
