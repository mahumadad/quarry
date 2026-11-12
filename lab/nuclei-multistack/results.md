# Resultados del laboratorio Nuclei multistack

- Generado: 2026-10-26T14:25:28.861784+00:00
- Resultado global: **PASS**
- Falsos negativos: 0
- Falsos positivos: 0

| Stack | Modo | Esperados | Detectados | FN | FP | Inesperados | Artefactos |
|---|---|---:|---:|---:|---:|---:|---|
| fastapi | vulnerable | 2 | 2 | 0 | 0 | 0 | íntegros |
| fastapi | secure | 2 | 0 | 0 | 0 | 0 | íntegros |
| django | vulnerable | 3 | 3 | 0 | 0 | 0 | íntegros |
| django | secure | 3 | 0 | 0 | 0 | 0 | íntegros |
| express | vulnerable | 4 | 4 | 0 | 0 | 0 | íntegros |
| express | secure | 4 | 0 | 0 | 0 | 0 | íntegros |

Los targets son exclusivamente loopback. Los valores sensibles son fixtures falsos.
Cero leads en el modo seguro es un control de especificidad, no una prueba general de ausencia.
