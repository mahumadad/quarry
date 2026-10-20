---
name: pt:scope
description: Muestra o modifica el scope del engagement activo — agregar/quitar reglas, ver estado actual
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /pt:scope [--add|--remove|--show]

Único comando (junto con `/pt:engage`) que puede modificar
`.pentest-state/scope.json`. Cualquier cambio de scope afecta
inmediatamente al guard de `hooks/hooks.json` en la próxima llamada Bash
— no requiere reiniciar sesión.

Sin argumento: equivalente a `--show`.

## Precondición

- Debe existir un engagement activo con scope ya inicializado por
  `/pt:engage`. Si no existe `.pentest-state/scope.json`, señalar que
  falta `/pt:engage` — este comando no crea un engagement desde cero.

## `--show` (default)

1. Cargar `Scope.load(Path("<audit_dir>/.pentest-state/scope.json"))`.
2. Mostrar en tabla: in-scope (patrón, tipo, notas), out-of-scope
   (patrón, tipo, notas), reglas del engagement, referencia de
   autorización.
3. Si hay assets descubiertos en `coverage.json` que no matchean
   ninguna entrada in-scope ni out-of-scope (zona gris — ej. un
   subdominio nuevo bajo un wildcard no explícito), listarlos aparte
   como "sin clasificar, requiere decisión del operador".

## `--add`

1. Preguntar: ¿in-scope o out-of-scope?, patrón (dominio/IP/CIDR/
   wildcard/URL), tipo, notas opcionales.
2. Validar el patrón sintácticamente antes de guardar (IP válida, CIDR
   parseable, dominio bien formado) — usar la misma lógica de
   `Scope._matches`/`_ip_in_cidr` para pre-chequear, no solo guardar
   texto libre.
3. Si se agrega a **in-scope**: confirmar explícitamente con el
   operador que esto está cubierto por la autorización existente, o que
   hay una nueva autorización para esta ampliación — no asumir que
   "agregar" implica automáticamente que está autorizado. Pedir
   referencia si es una ampliación real de alcance, no solo un detalle
   más fino del alcance ya autorizado.
4. Guardar con `Scope.add_in_scope(...)` / `add_out_of_scope(...)` y
   `Scope.save(...)`.
5. Si el patrón agregado a out-of-scope coincide con algo ya probado en
   `coverage.json` o con un finding existente en `findings.json`:
   advertir al operador — puede necesitar decidir qué pasa con ese
   trabajo ya hecho (¿se descarta del reporte? ¿se mantiene porque se
   hizo antes de la exclusión?).

## `--remove`

1. Pedir el patrón exacto a remover (de in-scope o out-of-scope —
   preguntar cuál si no es obvio).
2. Mostrar la entrada completa antes de borrar y confirmar.
3. Si se remueve una entrada **in-scope** que tiene findings asociados
   (`target_asset` matchea el patrón en `findings.json`): detener y
   advertir explícitamente — remover scope no debe borrar ni invalidar
   findings ya registrados silenciosamente. Preguntar si realmente se
   quiere remover (deja esos findings "huérfanos" de scope activo, pero
   el reporte histórico los mantiene) o si lo que se quiere es otra
   cosa (ej. pausar pruebas nuevas ahí, sin retirar el scope formal).
4. Guardar cambios.

## Edge cases

- **Remover la única entrada in-scope** (deja el scope vacío): advertir
  que esto bloquea cualquier acción ofensiva futura (regla de
  `CLAUDE.md` del plugin: sin scope, no hay acciones) y confirmar que es
  intencional (ej. engagement pausado).
- **Patrón duplicado o que se superpone con uno existente** (ej.
  agregar `*.amplifica.io` cuando ya existe `app.amplifica.io`):
  señalarlo, no bloquear — puede ser intencional (ampliar de un
  subdominio a todo el wildcard), pero el operador debe confirmarlo
  conscientemente.
- **Conflicto in-scope vs out-of-scope** (el mismo patrón, o uno que
  cubre al otro, en ambas listas): `Scope.is_in_scope` ya resuelve esto
  dando prioridad a out-of-scope, pero señalarlo igual como
  configuración confusa que vale la pena limpiar.
- **`--add`/`--remove` sin especificar tipo ni patrón**: preguntar, no
  inferir del contexto de la conversación salvo que sea inequívoco.

## Output esperado

- Tabla de scope resultante tras cualquier cambio (siempre mostrar el
  estado final, no solo "listo").
- Si hubo advertencias (findings huérfanos, scope vacío, superposición),
  listarlas explícitamente antes de confirmar que el cambio se guardó.
