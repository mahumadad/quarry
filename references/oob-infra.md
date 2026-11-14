# Self-hosted OOB / OAST infrastructure

Public `oast.*` / Collaborator-style servers are **shared infrastructure**: anyone running
the same service can see callback metadata, and the hostnames you inject land in third-party
logs. For engagements under NDA or with data-residency requirements, run your own OOB server.
This is the operational recipe behind the `oob-interactions` skill; correlation discipline and
evidence promotion stay with that skill and `engine/oast.py`.

## What you need

- A **dedicated domain** (or subdomain you fully control), separate from any client-identifying
  name — e.g. `oob.z3ro-m4d.example`. Never encode the client's name into the OOB domain.
- A **VPS** with a stable public IP and ports **53/udp+tcp** (DNS), **80**, **443** reachable.
- `interactsh-server` (ProjectDiscovery) installed on the VPS.

## DNS delegation

Delegate the OOB zone to the VPS so it is authoritative for every `<token>.<domain>` lookup:

1. At the registrar/parent zone, add glue + delegation:
   ```
   oob.example.      IN  NS   ns1.oob.example.
   ns1.oob.example.  IN  A    <VPS_PUBLIC_IP>
   ```
2. Confirm delegation propagated before testing:
   ```bash
   dig NS oob.example +short
   dig A test.oob.example @<VPS_PUBLIC_IP> +short   # must hit your server, not time out
   ```

DNS-only vectors (blind SQLi exfil, blocklist-resolve checks) depend on this delegation working;
without it you get HTTP callbacks but miss DNS-only interactions.

## Running the server

```bash
interactsh-server \
  -domain oob.example \
  -ip <VPS_PUBLIC_IP> \
  -token "$(openssl rand -hex 24)" \        # auth token: clients must present it
  -tls-mode letsencrypt                      # or supply -cert/-key for your own TLS
```

- **Auth token is mandatory.** Without `-token`, anyone who finds the server can pull your
  interaction log. Store the token in the engagement vault, not in shell history.
- **TLS** (443) lets HTTPS-only fetchers call back; Let's Encrypt needs ports 80/443 open and the
  domain's A record pointing at the VPS.

## Client side

```bash
interactsh-client -server https://oob.example -token "$OOB_TOKEN" -json -o interactions.jsonl
```

Feed the minted hostnames into payloads as the `oob-interactions` skill directs (one unique token
per injection). `engine/oast.py` (`OASTManager`) mints and correlates tokens; point it at your
self-hosted server's domain/token for the engagement rather than a public default.

## Logs, retention, hygiene

- Keep `interactions.jsonl` inside the engagement's evidence store; it is custody-grade proof of
  blind findings. Rotate/retain per the engagement's data-retention policy (`data-retention`
  skill), and destroy it at closeout along with other engagement data.
- **Verify callbacks are yours.** The server should only surface interactions whose token this
  engagement minted — an unmatched hit is internet background noise, never evidence (see the
  correlation tiers in `oob-interactions`). Confirm `remote_addr` belongs to target infra before
  promoting to Demonstrated.
- Tear the server down (or rotate the domain + token) between unrelated engagements so callbacks
  never cross client boundaries.

## Alternatives when a full server is overkill

- **Burp Collaborator** (private instance, if licensed) — same self-hosting benefit, integrated
  with Burp.
- **Own listener** for a single vector: a VPS with `python3 -m http.server` + access log for
  HTTP-only callbacks, or `dnsmasq` / an authoritative resolver with query logging for DNS-only
  vectors. Lower fidelity (no unified correlation UI) but fine for a one-off blind confirmation.
