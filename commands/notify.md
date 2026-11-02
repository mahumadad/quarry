---
name: pt:notify
description: Immediately escalate a critical finding to stakeholders
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /pt:notify — Escalación inmediata de hallazgo crítico

Uso: `/pt:notify <finding_id>`

## Cuándo es OBLIGATORIO

- Finding crítico confirmado en PRODUCCIÓN (RCE, acceso masivo a datos,
  toma de cuenta admin) — se notifica el mismo día, no en el reporte.
- Evidencia de compromiso PREVIO del target (webshell ajeno, credenciales
  del cliente en leaks, actividad de otro actor) — el cliente puede tener
  un incidente activo; tu engagement pasa a segundo plano.
- Acción fuera de scope ejecutada por error — transparencia inmediata.
- Hallazgo con riesgo de seguridad física o legal (datos de menores,
  infra crítica).

## Protocolo

1. **Congelar la línea de ataque**: no seguir explotando el finding crítico
   hasta que el cliente confirme recepción — un RCE en prod sigue siendo
   prod.
2. Completar `templates/critical-alert.md`: veredicto, evidencia mínima
   suficiente para actuar, qué NO tocar, mitigación inmediata sugerida.
3. Enviar por el canal de emergencia definido en `/pt:engage`
   (emergency_contact). Cifrar si el canal no es de confianza
   (`/pt:deliver` con gpg aplica para adjuntos).
4. Registrar el envío en custody (actor: operator, evento: critical_alert).
5. Reanudar el engagement solo tras ack del cliente (o decisión documentada
   del operador si el cliente no responde en lo acordado).

## Reglas

- La alerta contiene lo mínimo para actuar — el detalle completo va en el
  reporte. Evidencia sensible (datos reales extraídos) NO va en el alert.
- Si el canal de emergencia falla, escalar por el contacto secundario y
  registrar ambos intentos en custody.
- Nunca publicar/compartir el hallazgo fuera del canal acordado —
  incluyendo "aviso anónimo al vendor" — sin autorización del cliente.
