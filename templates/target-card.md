# Target Card — {{target_name}}

> Metodología de las 5 preguntas (DarkMarc). Se completa ANTES de hunting,
> idealmente al cierre de la fase de recon/mapping. El objetivo es forzar
> un modelo mental explícito del target antes de empezar a probar vulns
> individuales — la mayoría de cadenas de alto impacto se ven acá, no
> durante el hunting ad-hoc.

**Target:** {{target_name}}
**Scope:** {{scope_summary}}
**Fecha:** {{date}}
**Completado por:** {{operator}}

---

## 1. ¿Cuáles son los untrusted inputs?

Todo punto donde el sistema acepta datos que no controla: parámetros HTTP,
headers, cookies, JSON bodies, uploads de archivos, mensajes de cola,
webhooks entrantes, campos de formularios, variables de entorno expuestas
vía API, metadata de archivos subidos, respuestas de servicios de terceros
que el target consume sin validar.

| Input | Tipo | Dónde se consume | Validación observada |
|---|---|---|---|
| {{input_1}} | {{type_1}} | {{consumer_1}} | {{validation_1}} |
| {{input_2}} | {{type_2}} | {{consumer_2}} | {{validation_2}} |

**Nota:** un input "de confianza" (ej. un JWT firmado por el propio sistema)
puede seguir siendo untrusted si el atacante controla su contenido antes de
que se firme, o si puede obtener uno legítimo con bajo privilegio.

## 2. ¿Qué tools/capabilities tiene el target, ordenadas por severidad?

Listar las *capacidades* del sistema — no vulnerabilidades, sino qué puede
hacer el sistema per se. Una capacidad de alta severidad convierte un bug
menor en crítico (ej. "puede ejecutar shell commands" + "command injection
menor" = RCE).

Ordenar de mayor a menor severidad potencial si un atacante la controla:

| # | Capability | Qué permite si se abusa | Severidad si comprometida |
|---|---|---|---|
| 1 | {{capability_1}} | {{abuse_1}} | Critical |
| 2 | {{capability_2}} | {{abuse_2}} | High |
| 3 | {{capability_3}} | {{abuse_3}} | Medium |

Ejemplos de capacidades a buscar explícitamente: ejecución de código
(sandboxes, workers, plugins), fetch de URLs arbitrarias (webhooks, PDF
generators, SSR, image proxies), acceso a filesystem, acceso a BD con
privilegios amplios, envío de emails/SMS, integración con cloud provider
(IAM role, service account), generación de tokens/JWTs, acceso a secrets
manager, capacidad de ejecutar queries dinámicas.

## 3. ¿Cuál es el modelo de privilegio/identidad?

Mapear roles, cómo se determina el privilegio en cada request, y dónde
podría romperse el aislamiento entre identidades.

- **Roles existentes:** {{roles_list}}
- **Cómo se determina el rol en cada request:** {{auth_mechanism}} (JWT claim, session lookup, header, cookie)
- **¿El servidor revalida el privilegio en cada acción o confía en el cliente?** {{server_side_revalidation}}
- **Multi-tenancy:** {{tenancy_model}} (aislamiento por fila/schema/DB/instancia)
- **Trust boundaries entre servicios internos:** {{internal_trust}} (¿microservicios confían ciegamente entre sí vía red interna?)
- **Impersonation/delegation:** {{impersonation}} (¿existen roles que pueden actuar como otro usuario — soporte, admin-as-user?)

**Pregunta clave:** si obtengo una identidad de privilegio bajo, ¿qué objetos
de un privilegio alto puedo tocar solo porque el control de acceso se
implementó a nivel de UI y no a nivel de servidor/objeto?

## 4. ¿Qué downstream interpreters existen?

Cualquier punto donde el input del usuario (directo o indirecto) termina
siendo interpretado por otro motor con su propia sintaxis.

| Interpreter | Dónde aparece | Input que llega | Sanitización observada |
|---|---|---|---|
| SQL | {{sql_location}} | {{sql_input}} | {{sql_sanitization}} |
| Shell/OS command | {{shell_location}} | {{shell_input}} | {{shell_sanitization}} |
| URL fetch (SSRF surface) | {{url_fetch_location}} | {{url_fetch_input}} | {{url_fetch_sanitization}} |
| Template engine (SSTI) | {{template_location}} | {{template_input}} | {{template_sanitization}} |
| Deserializer | {{deser_location}} | {{deser_input}} | {{deser_sanitization}} |
| LDAP/NoSQL query | {{nosql_location}} | {{nosql_input}} | {{nosql_sanitization}} |
| Regex engine (ReDoS) | {{regex_location}} | {{regex_input}} | {{regex_sanitization}} |
| XML parser (XXE) | {{xml_location}} | {{xml_input}} | {{xml_sanitization}} |

Cada interpreter es un punto de pivoteo potencial: un input que llega "limpio"
a un interpreter pero "sucio" a otro (porque cada uno sanitiza distinto) es
una clase de bug recurrente (second-order injection).

## 5. ¿Cuáles son los output sinks (rutas de exfiltración)?

Dónde puede salir información del sistema hacia donde el atacante la puede
leer — no solo responses HTTP directas.

| Sink | Mecanismo | Visibilidad para el atacante |
|---|---|---|
| Response body directo | {{sink_1_mechanism}} | Inmediata |
| Error messages/stack traces | {{sink_2_mechanism}} | Inmediata |
| Timing side-channel | {{sink_3_mechanism}} | Requiere medición |
| Out-of-band (DNS/HTTP callback) | {{sink_4_mechanism}} | Requiere listener propio (interactsh, Burp Collaborator) |
| Logs expuestos | {{sink_5_mechanism}} | Requiere acceso a logs |
| Emails/notificaciones salientes | {{sink_6_mechanism}} | Requiere control de la bandeja destino |
| Cloud metadata endpoint | {{sink_7_mechanism}} | Inmediata si hay SSRF |
| Cache compartido (cache poisoning) | {{sink_8_mechanism}} | Afecta a otros usuarios |

**Pregunta clave para blind vulns:** si la vulnerabilidad no refleja output
directo, ¿cuál de estos sinks puedo usar para confirmar explotación sin
depender de una respuesta visible?

---

## Síntesis para hunting

A partir de las 5 respuestas, priorizar hunting hacia las combinaciones de
mayor leverage: inputs untrusted (1) que alimentan interpreters (4) detrás
de un modelo de privilegio débil (3), con capacidades de alta severidad (2)
alcanzables, y al menos un sink confiable (5) para demostrar impacto incluso
si la vuln es blind.

**Top 3 vectores priorizados para esta target card:**

1. {{priority_vector_1}}
2. {{priority_vector_2}}
3. {{priority_vector_3}}
