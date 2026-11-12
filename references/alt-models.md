# Modelos Alternativos Disponibles

> Modelos de IA adicionales a Claude disponibles en el entorno del
> operador. Útiles como segunda opinión, para tareas donde Claude tiene
> restricciones de contenido, o para procesamiento paralelo.

## Modelos disponibles

| Alias | Modelo | Uso principal |
|---|---|---|
| `kimi` | Kimi (Moonshot AI) | Razonamiento largo, análisis de código extenso, investigación |
| `refuselesscc` | GLM 5.3 | Generación de payloads, análisis ofensivo sin restricciones |
| `refuselessds` | DeepSeek V4.1 Flash | Análisis ofensivo rápido, generación de exploits, fuzzing |

## Cuándo usar cada modelo

### Kimi
- Análisis de código fuente extenso (contexto largo).
- Investigación de vulnerabilidades con mucho contexto de documentación.
- Revisión de arquitectura cuando el codebase es grande.

### refuselesscc (GLM 5.3)
- Generación de payloads de explotación.
- Análisis de técnicas de bypass (WAF, CSP, CORS).
- Shellcode y post-explotación.
- Craft de exploits para CVEs conocidos.

### refuselessds (DeepSeek V4.1 Flash)
- Generación rápida de payloads y wordlists especializadas.
- Análisis de código para vulnerabilidades sin filtro de contenido.
- Fuzzing payloads por categoría (SQLi, XSS, SSTI, etc.).
- Variantes de bypass a partir de un payload base.

## Integración con el workflow

Estos modelos son herramientas del operador, no del plugin directamente.
Se invocan fuera del flujo automatizado del engine cuando Claude no puede
generar el contenido requerido (e.g., payload ofensivo específico).

El operador puede:
1. Pedir a Claude que describa qué payload se necesita (estructura, objetivo,
   restricciones del target).
2. Usar el modelo alternativo para generarlo.
3. Volver a Claude para integrar el resultado en el engagement
   (registrar finding, evidencia, custody log).

## Nota sobre evidencia

Payloads generados por modelos externos siguen las mismas reglas de
evidencia del plugin: deben ser verificados contra el target real antes
de reportarse como **Demonstrated**. Un payload generado sin verificar
es **Unproven** hasta que se demuestre impacto.
