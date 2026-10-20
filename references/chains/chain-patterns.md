# Chain Patterns — Explicación detallada

> La chain-matrix.md dice QUÉ combina con qué. Este documento explica POR
> QUÉ combinan: qué capacidad otorga el finding A que el finding B
> necesita para avanzar. Entender el "por qué" permite reconocer variantes
> del mismo patrón que no calzan exactamente con la matriz literal.

## Patrón: Acceso de lectura + ausencia de fricción → exfiltración masiva

**Ejemplos en la matriz:** #1 (IDOR + no rate limit), #32 (IDOR en export + IDs secuenciales)

**Por qué chainea:** un IDOR de lectura por sí solo demuestra acceso a *un*
objeto ajeno — impacto limitado a ese registro. Lo que lo convierte en
crítico no es el bug de autorización en sí, sino la ausencia de cualquier
control que limite *cuántas veces* se puede repetir la misma técnica. El
finding A (IDOR) provee la *técnica* de acceso; el finding B (sin rate
limit, IDs predecibles/secuenciales) provee la *escala*. Ninguno de los dos
por separado es "dump del padrón completo" — la combinación sí.

**Variantes a reconocer:** paginación sin límite máximo expuesta vía API,
exportación en bulk que no valida ownership de cada ID en el batch,
endpoints de búsqueda que permiten wildcard sin paginación forzada.

## Patrón: Inyección de contenido + ausencia de verificación de intención → account takeover

**Ejemplos en la matriz:** #2 (XSS + CSRF)

**Por qué chainea:** el XSS almacenado da *ejecución de código en el
contexto de la víctima* — puede leer su DOM, robar tokens, hacer requests
con su sesión. El CSRF (o la ausencia de protección equivalente) significa
que el servidor no verifica que la acción vino de una intención real del
usuario, solo que vino con sus credenciales de sesión. El XSS resuelve "¿cómo
logro que se ejecute código en la sesión de la víctima sin que haga nada?"
y el CSRF resuelve "¿el servidor va a confiar en esa request sin pedir
re-autenticación ni token?". Juntos: tomar control de la cuenta sin que la
víctima haga click en nada adicional al cargar la página con el XSS.

**Variantes a reconocer:** XSS reflejado que solo requiere que la víctima
abra un link (igual de crítico si el flujo de distribución del link es
viable), self-XSS que se vuelve explotable vía un CSRF que fuerza la
víctima a "pegar" el payload (encadenamiento inverso).

## Patrón: Fetch de URL controlado + superficie de red privilegiada → robo de credenciales de infraestructura

**Ejemplos en la matriz:** #3 (SSRF + cloud metadata), #28 (SSRF + API de orquestador)

**Por qué chainea:** el SSRF da la *capacidad de hacer que el servidor
haga una request a donde el atacante elige* — pero por sí solo, si apunta a
un recurso sin valor (ej. un `httpbin` de prueba), es solo una curiosidad.
El valor explota cuando el *destino* de ese fetch es un servicio que asume
que solo el propio sistema puede alcanzarlo — el endpoint de metadata de
cloud (`169.254.169.254` y equivalentes) o una API de gestión interna
(Docker socket, Kubernetes API, paneles de administración sin autenticación
porque "están en la red interna"). El SSRF rompe el supuesto "solo el
servidor puede llegar ahí"; el servicio interno confía ciegamente en
cualquiera que llegue.

**Variantes a reconocer:** SSRF vía parser de PDF/imagen que sigue
referencias externas, SSRF vía webhook configurable por el usuario, SSRF
vía integración con servicio de terceros que resuelve URLs provistas por
el usuario (ej. preview de links).

## Patrón: Confianza en claims del cliente + control de acceso roto a nivel de objeto → impersonación

**Ejemplos en la matriz:** #8 (JWT alg none + IDOR), #16 (Mass assignment + campo de rol)

**Por qué chainea:** el primer finding da *control sobre qué identidad
afirma tener la request* (un JWT manipulable, o un campo de rol que se
puede enviar en un payload que el backend no debería aceptar del cliente).
El segundo finding es que el backend, en el punto donde importa, confía en
esa identidad afirmada sin revalidarla contra el estado real en la base de
datos. El primer finding sin el segundo es "puedo mentir sobre quién soy"
sin que nadie lo escuche; el segundo sin el primero es "el sistema confía
en lo que declaro" pero sin forma de declarar algo falso. Juntos: declarar
ser admin y que el sistema lo crea.

**Variantes a reconocer:** headers de autorización custom que el backend
confía (`X-User-Role`), parámetros de query que sobreescriben el contexto
de sesión, GraphQL mutations que aceptan campos de autorización en el
input sin filtrarlos server-side.

## Patrón: Primitiva de escritura sin restricción de tipo/ubicación + ejecución condicionada por tipo/ubicación → RCE

**Ejemplos en la matriz:** #7 (file upload + path traversal), #29 (LFI + log poisoning)

**Por qué chainea:** la primera mitad da *control sobre contenido que
termina en el filesystem del servidor* (un archivo subido, una línea de
log con contenido controlado por el atacante vía header). La segunda mitad
da *un camino para que ese contenido se interprete como código* (el
servidor sirve/ejecuta archivos de una ubicación que el path traversal
permite alcanzar, o el sistema incluye el archivo de log como si fuera
código vía LFI). Ninguna mitad es RCE sola: subir un archivo sin poder
alcanzarlo desde donde se ejecuta código es inofensivo; poder incluir
arbitrariamente un archivo sin controlar su contenido tampoco lo es.

**Variantes a reconocer:** upload de archivos con extensión controlada por
el usuario en un stack donde el servidor web ejecuta por extensión, control
parcial de un archivo de configuración incluido dinámicamente.

## Patrón: Revelación de estructura interna + superficie de autorización incompleta → escalada de privilegio dirigida

**Ejemplos en la matriz:** #4 (info disclosure + auth bypass), #15 (GraphQL introspection + falta de autorización por campo)

**Por qué chainea:** la revelación de estructura (stack traces, schema de
GraphQL, rutas internas en comentarios/JS) no es explotación — es *mapa*.
Reduce drásticamente el espacio de búsqueda para encontrar el punto exacto
donde la autorización está incompleta. Sin el mapa, encontrar ese punto
específico puede requerir fuzzing extenso o no encontrarse en el tiempo del
engagement; con el mapa, se prueba directamente contra el endpoint/campo
que el mapa señala.

**Variantes a reconocer:** comentarios de código fuente expuestos en JS de
producción, mensajes de error que revelan nombres de tablas/columnas,
documentación de API interna accesible sin autenticación (Swagger/OpenAPI
expuesto sin estar destinado a ser público).

## Cómo generalizar más allá de estos patrones

Para cualquier par de findings nuevo, preguntarse explícitamente:

1. ¿Qué *capacidad* otorga el finding A (acceso, control de contenido,
   información, bypass de una verificación)?
2. ¿Qué *precondición* necesita el finding B para escalar su impacto, y la
   capacidad de A la satisface?
3. ¿El impacto combinado es *cualitativamente* distinto (cruza un trust
   boundary que ninguno cruzaba solo) o solo *cuantitativamente* mayor
   (más datos, más veces)? Ambos son chains válidas, pero el primero
   generalmente justifica Scope: Changed en el CVSS combinado.

Si la respuesta a 1 y 2 es clara y verificable, es una chain real —
documentarla en `chain-report.md` y, si se confirma en más de un
engagement, proponerla como fila nueva en `chain-matrix.md`.
