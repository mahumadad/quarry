---
name: pt:engage
description: Inicia un nuevo engagement de pentest — scope, directorio de auditoría, target card
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /pt:engage <target>

Inicializa un engagement nuevo. Es el único comando que puede crear un
engagement desde cero; todos los demás comandos requieren que este haya
corrido primero y haya scope confirmado.

## Argumento

`<target>` — nombre o dominio principal del target (ej. `amplifica.io`,
`fazt.cl`). Obligatorio. Si falta, pedirlo antes de continuar.

## Edge cases primero

- Si ya existe un engagement activo (hay `.pentest-state/engagement.json`
  en el directorio de auditoría resuelto para este target) y su fase no es
  `closed`: mostrar el estado actual (fase, scope, findings) y preguntar
  si se retoma ese engagement o se crea uno nuevo con sufijo de fecha. No
  sobrescribir silenciosamente.
- Si el operador no puede dar una referencia de autorización verificable
  (correo, carta, contrato, programa de bug bounty con alcance publicado):
  **detener el comando**. Sin autorización no hay engagement. Esto no es
  negociable — es la regla #1 de `CLAUDE.md` del plugin.
- Si el target coincide con un dominio/IP ya marcado out-of-scope en un
  engagement previo del mismo operador (si se encuentra un audit dir
  hermano), advertir antes de continuar.

## Pasos exactos

1. **Resolver directorio de auditoría.** Convención de este operador:
   `~/Dev/personal/<slug>_audit/`, donde `<slug>` es el target en
   minúsculas, sin protocolo, con `.` y caracteres no alfanuméricos
   reemplazados por `-` (ej. `app.amplifica.io` → `amplifica-io_audit`,
   pero preferir el nombre de marca corto si el operador lo da, ej.
   `amplifica_audit`, `fazt_audit`, `portalnet_audit` — estos ya existen
   como precedente). Preguntar al operador si quiere ese path u otro
   antes de crear nada.

2. **Pedir y confirmar scope — explícitamente, antes de tocar el target:**
   - Dominios/IPs/CIDRs **in-scope** (uno o más).
   - Dominios/IPs/rutas **out-of-scope** (si no hay ninguno, preguntar
     "¿todo lo que resuelva bajo este target está en scope, o hay
     exclusiones?" — no asumir "ninguna exclusión" por omisión).
   - **Referencia de autorización**: quién autorizó, cómo (correo/carta/
     programa), fecha. Guardar el texto o enlace tal cual, no resumido.
   - **Reglas del engagement**: horarios permitidos, rate limits, técnicas
     prohibidas (ej. "no DoS", "no ingeniería social con empleados reales",
     "no destructivo en prod"), y si requiere notificación previa a la
     explotación.
   - Mostrar el scope completo de vuelta al operador en una tabla y pedir
     confirmación explícita ("¿confirmas este scope?") antes de guardar
     nada. Si el operador corrige algo, repetir la confirmación.

3. **Generar la target card (5 preguntas).** Formato de
   `templates/target-card.md` si el archivo existe; si no, usar esta
   estructura inline y, en ese caso, avisar que el template no está
   escrito todavía:
   1. ¿Qué es el target? (producto/empresa/organización, qué hace, quién
      lo usa)
   2. ¿Cuáles son los crown jewels? (qué dato o función, si se compromete,
      hace crítico el engagement — PII, dinero, credenciales admin, etc.)
   3. ¿Quién es el contacto/autorización? (nombre, rol, referencia del
      paso 2)
   4. ¿Qué está explícitamente fuera de scope o prohibido?
   5. ¿Cuál es la ventana del engagement y las reglas de tiempo/tasa?

   Rellenar la target card con las respuestas del operador. Si alguna
   respuesta es ambigua, preguntar de nuevo — no inferir.

4. **Crear el directorio de auditoría** con `mkdir -p`:
   ```
   <audit_dir>/
   ├── .pentest-state/
   ├── raw/           # output crudo de herramientas
   ├── evidence/      # PoCs, capturas, request/response
   └── report/        # drafts y reporte final
   ```

5. **Inicializar el estado del engine** (usa `engine/state.py` vía Python,
   con `${CLAUDE_PLUGIN_ROOT}/engine` en `sys.path`):
   ```bash
   python3 -c "
   import sys; sys.path.insert(0, '${CLAUDE_PLUGIN_ROOT}/engine')
   from state import EngagementState, Phase
   s = EngagementState('<audit_dir>')
   s.initialize('<engagement_id>', '<target>', metadata={'target_card': <dict>})
   print(s.to_dict())
   "
   ```
   `<engagement_id>` sugerido: `<slug>-<YYYYMMDD>`.

6. **Guardar el scope** con `engine/scope.py`:
   ```python
   from scope import Scope
   sc = Scope(authorization="<referencia>", rules=[...])
   sc.add_in_scope("<pattern>", "<domain|ip|cidr|wildcard>", notes="...")
   sc.add_out_of_scope(...)
   sc.save(Path("<audit_dir>/.pentest-state/scope.json"))
   ```

7. **Transicionar la fase** `INIT → SCOPED` con `s.transition(Phase.SCOPED)`.
   Si `can_transition` devuelve `False` (no debería en un engagement nuevo),
   reportarlo y detenerse — es una señal de estado corrupto, no algo para
   forzar.

8. **Escribir la target card** como `<audit_dir>/report/target-card.md`
   (Write tool) con las 5 respuestas y el scope resuelto.

## Output esperado

- Confirmación en una tabla: target, slug, audit dir, fase actual (SCOPED),
  scope in/out, referencia de autorización.
- Ruta de la target card escrita.
- Próximo paso recomendado: `/pt:recon` (full, por defecto).

No ejecutar ningún scan, request HTTP, ni herramienta de descubrimiento en
este comando — `/pt:engage` solo establece scope y estado. Cualquier
tentación de "adelantar" recon aquí se rechaza explícitamente: eso es
trabajo de `/pt:recon` y debe correr con el scope ya persistido y el guard
de `hooks/hooks.json` activo.
