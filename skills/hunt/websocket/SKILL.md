---
name: hunt-websocket
description: >
  Hunt for WebSocket security issues: Cross-Site WebSocket Hijacking (CSWSH) from missing
  origin validation, missing/weak authentication on the upgrade handshake, unvalidated
  message content enabling tampering, and authorization checks skipped for actions
  triggered via WebSocket messages (vs. equivalent REST endpoints). Use on any target
  using `ws://`/`wss://` for real-time features (chat, live updates, trading, collab
  editing).
  Keywords: WebSocket, CSWSH, cross-site websocket hijacking, ws upgrade, origin
  validation, websocat, Sec-WebSocket-Protocol, message tampering, socket.io auth.
  Do NOT use for generic CSRF on standard HTTP forms (hunt-csrf) — CSWSH is the WebSocket-
  specific variant with its own handshake mechanics covered here.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-346, CWE-306, CWE-862]
  mitre_attack: [T1190]
  tools: [websocat, burpsuite, curl, "browser devtools"]
depends_on: [active-recon, web-crawling]
feeds_into: [chain-analysis, auth-bypass]
chains_with: [hunt-csrf, hunt-broken-access-control, hunt-auth-bypass]
---

## Signals

- Any `ws://` or `wss://` connection initiated by the app (visible in browser devtools
  Network tab under the "WS" filter, or in a proxy history as a `101 Switching Protocols`
  response).
- The WebSocket upgrade handshake relies on an ambient credential (session cookie) for
  authentication rather than an explicit token sent as the first application-level message
  after connection — ambient-credential auth is exactly what makes CSWSH possible if origin
  isn't also checked.
- No `Origin` header validation server-side on the upgrade request — test by attempting
  the handshake from a different origin's context (see Methodology step 2).
- `ws://` (unencrypted) used instead of `wss://` for any session carrying authenticated
  traffic, exposing messages to network-level tampering/eavesdropping.
- Server-side logic that trusts fields inside WebSocket messages (`userId`, `role`,
  `roomId`) without re-validating them against the authenticated session tied to that
  socket, mirroring IDOR/broken-access-control patterns but inside the message payload
  instead of a URL/body param.
- Reconnect/resume logic that re-authenticates differently (or not at all) compared to the
  initial connection.

## Prerequisites

- Two authenticated test accounts with different privilege levels or resource ownership,
  for the authorization tests in step 4.
- `websocat` installed and its `--help` reviewed (flags vary notably between versions) for
  scripted connection/message testing outside the browser.
- A way to observe the exact handshake request/response — Burp's WebSocket history view or
  browser devtools' WS frame inspector.

## Methodology

1. **Capture the handshake and message schema.** Open the feature in a browser, capture
   the full upgrade request (headers, especially `Cookie`, `Origin`, any auth-related
   custom header) and the first several application-level messages exchanged, to establish
   a baseline schema:
   ```bash
   # Burp: Proxy > WebSockets history, or browser devtools Network > WS > Messages tab
   ```

2. **Origin validation / CSWSH test.** Reconstruct the handshake using `websocat` (or a
   minimal HTML page opened from a different origin) sending the victim's session cookie
   but an attacker-controlled `Origin` header, and confirm whether the server completes the
   upgrade and starts sending authenticated data:
   ```bash
   websocat -H "Origin: https://attacker-controlled-origin.example" \
            -H "Cookie: session=$VICTIM_SESSION_COOKIE" \
            wss://target/ws/endpoint
   ```
   The browser's same-origin policy doesn't block cross-origin WebSocket connections by
   default the way it blocks cross-origin `fetch` reads — this is exactly why server-side
   `Origin` validation is the control that matters, not the browser.

3. **Unauthenticated/under-authenticated upgrade test.** Attempt the handshake with no
   cookie/token at all, and separately with an expired/invalidated one, to confirm the
   server actually rejects the upgrade rather than silently falling back to an anonymous or
   stale-but-still-trusted state:
   ```bash
   websocat wss://target/ws/endpoint   # no auth material at all
   ```

4. **Message-level authorization bypass.** Once connected as account A, send messages
   referencing resources/IDs belonging to account B (mirroring the IDOR pattern, but over
   the socket's message protocol) and check whether the server enforces ownership:
   ```bash
   websocat wss://target/ws/endpoint <<< '{"type":"join_room","roomId":"<account_B_private_room_id>"}'
   ```
   Confirm by observing whether account B's private data/actions become visible or
   executable from account A's connection.

5. **Message tampering / input validation check.** Send malformed or boundary-violating
   values for fields the server trusts without re-validating (negative amounts, foreign
   IDs, oversized payloads, unexpected types) and observe whether server-side logic
   processes them as if they were valid client UI constraints rather than untrusted input:
   ```bash
   websocat wss://target/ws/endpoint <<< '{"type":"transfer","amount":-500,"to":"<other_account_id>"}'
   ```

6. **Transport confirmation.** Verify whether the connection negotiated `wss://` (TLS) and
   whether any fallback to plaintext `ws://` is possible/observed (e.g., via a
   misconfigured reverse proxy or a mixed-content allowance).

7. **Compare against the equivalent REST/HTTP authorization logic**, if one exists for the
   same action — a mismatch where REST enforces an ownership/role check that the WebSocket
   handler skips is the core high-value finding this skill targets, and is strictly
   stronger evidence than either surface tested alone.

## Tooling

- `websocat` — scriptable WebSocket client for crafting and replaying handshakes/messages
  outside the browser; review `websocat --help` for the installed version's exact flag set
  before first use.
- Burp Suite's native WebSocket support (Proxy history WS tab, and message interception/
  replay) — the most practical tool for live interactive testing against a running session.
- Browser devtools Network panel (WS filter) for quick baseline capture without any extra
  tooling.

## Root Causes

- Authentication tied only to an ambient browser credential (cookie) at connection time,
  with no `Origin` allow-list check and no secondary token exchanged over the socket itself.
- Authorization logic written once for REST handlers and never ported to the WebSocket
  message handlers serving the equivalent functionality.
- Treating WebSocket message fields as trusted client state because they originated from
  the app's own JS, rather than as untrusted input needing the same validation as any HTTP
  parameter.

## Validation Gate (minimum proof)

- Minimum: an **actual unauthorized action or data access performed via a WebSocket
  message** — not just a successful connection. A cross-origin handshake that completes but
  is followed by only generic/non-sensitive data is Inferred at most; it becomes
  Demonstrated once you show the connection delivers or accepts something that should have
  required a different identity/origin.
- For CSWSH specifically: the handshake request with the attacker `Origin`, the server's
  acceptance (101 response), and the subsequent authenticated data/action actually
  retrieved/performed over that connection.
- For message-level authorization bypass: the exact message sent from account A's
  connection and the response/side effect showing access to account B's resource.

## Gotchas

- **Overclaim trap:** a successful cross-origin WebSocket connection alone, without any
  sensitive data flowing afterward, is not a full CSWSH finding — browsers don't block the
  connection by default regardless of vulnerability, so the connection succeeding is
  expected; the finding is in what happens after.
- **Common N/A:** the app exchanges a short-lived, connection-scoped token as the *first
  application message* after a generic-origin upgrade, and the server rejects any message
  before that token is validated — this pattern defeats ambient-credential-based CSWSH even
  without strict `Origin` checking; verify this flow exists before claiming CSWSH.
- **Common N/A:** socket.io (and similar libraries) deployed with its own handshake
  auth middleware actually enforcing checks — confirm by testing, not by library name alone;
  misconfiguration is common even with libraries that support secure patterns by default.
- A WebSocket connection that silently drops/closes on invalid auth is a different (better)
  outcome than one that stays open but simply doesn't respond to unauthorized messages —
  document which behavior you observed, since "connection stays open" sometimes gets
  mis-reported as a vulnerability on its own without a demonstrated action.
- Message schemas often change between app versions/features — don't assume a schema
  captured from one feature applies unmodified to another socket endpoint.

## Chains & Compositions

- Confirmed CSWSH delivering authenticated data to a cross-origin page → combine with a
  hosted PoC page requiring **explicit operator authorization** before any delivery
  mechanism beyond a controlled test is used (per human-gate rules).
- Message-level authorization bypass → feeds **hunt-broken-access-control** for the broader
  cross-account access assessment, and **auth-bypass** if it grants elevated session
  capabilities.
- Mismatch against REST-layer authorization already mapped in **hunt-csrf**/
  **hunt-broken-access-control** passes — cross-reference before closing either skill.
