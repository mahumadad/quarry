---
name: pt:deliver
description: Package and deliver engagement artifacts with optional GPG encryption
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /pt:deliver — Empaquetar y entregar los artefactos del engagement

Uso: `/pt:deliver <dir_entregable> [--gpg RECIPIENT | --gpg-symmetric]`

## Qué hace

1. Construye el manifest SHA-256 de TODOS los archivos del entregable
   (reporte, findings, evidencia, exports, custody log) vía
   `engine/deliver.py` → `manifest.json`.
2. Verifica el custody log una última vez (debe estar ÍNTEGRO antes de
   empaquetar — si está roto, NO entregar: investigar primero).
3. Genera el bundle `.tar.gz` con el manifest dentro.
4. Cifrado opcional con gpg (por destinatario o simétrico AES256) según el
   canal de entrega acordado con el cliente.
5. Registra el empaquetado en custody (hash del bundle incluido).

## Reglas

- El manifest es la garantía: el cliente puede re-verificar cualquier
  archivo contra él. Si algo difiere post-entrega, el manifest resuelve
  quién alteró qué.
- El bundle sin cifrar NUNCA va por canales no acordados (email corporativo
  genérico, links públicos).
- Guardar el hash del bundle entregado en custody — si el cliente reporta
  "el archivo no abre" o disputa contenido, el hash cierra la discusión.
- Entregar = evento custody con fecha, canal y destinatario.

## Ejemplos

```
/pt:deliver outputs/acme-2026-09/deliverable --gpg security@acme.com
/pt:deliver outputs/acme-2026-09/deliverable --gpg-symmetric
```
