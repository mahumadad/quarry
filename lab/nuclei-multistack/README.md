# Laboratorio Nuclei multistack

Banco de pruebas local para medir los templates Nuclei revisados contra aplicaciones reales, no solo contra respuestas HTTP sintéticas. Cada stack tiene una variante vulnerable y un control seguro construido desde la misma imagen.

## Alcance y seguridad

- Los seis servicios escuchan únicamente en `127.0.0.1`.
- `run_lab.py` no acepta targets externos: ejecuta solamente los seis casos declarados localmente.
- El runner crea un scope exclusivo para `127.0.0.1`, una ventana temporal y artefactos de evidencia por caso.
- Las credenciales y configuraciones sensibles son fixtures falsos, exclusivos del laboratorio.
- `.runtime/` contiene estado y evidencia temporales; se regenera en cada ejecución y no debe versionarse.

## Matriz

| Stack | Vulnerable | Seguro | Señales esperadas en la variante vulnerable |
|---|---:|---:|---|
| FastAPI | 18081 | 18084 | Documentación OpenAPI y `.env` |
| Django | 18082 | 18085 | Admin, páginas de debug y `.env` |
| Express | 18083 | 18086 | Stack trace, `.env`, `package.json` y source map |

El resultado correcto exige todos los leads esperados en la variante vulnerable, ningún lead inesperado y cero leads en el control seguro. También verifica la integridad de los artefactos.

## Ejecución

Requisitos: Docker con Compose, Python 3, las dependencias del proyecto y Nuclei 3.10.0 disponible en `PATH`.

Desde la raíz del repositorio:

```bash
docker compose -f lab/nuclei-multistack/docker-compose.yml up -d --build
python lab/nuclei-multistack/run_lab.py
docker compose -f lab/nuclei-multistack/docker-compose.yml down
```

`run_lab.py` devuelve código distinto de cero si falla cualquier caso. Los resultados se generan en `results.json` y `results.md`; no se editan manualmente.

## Interpretación y límites

Este laboratorio mide recall sobre las exposiciones sembradas y especificidad sobre estos controles concretos. No demuestra cobertura de todas las versiones, configuraciones o clases de vulnerabilidad, ni que un control seguro carezca de otros problemas. Los leads de superficie informativa todavía requieren validación y contexto antes de convertirse en hallazgos.

## Transición a bug bounty

Después de dejar el laboratorio en verde, cargar el engagement con programa, targets, scope, exclusiones, Rules of Engagement, ventana y límites. Ejecutar primero el plan `safe`. Las plantillas `sensitive-data` requieren que esa actividad esté permitida y una aprobación específica; participar en un programa no autoriza automáticamente todas las rutas, métodos o clases de prueba.
