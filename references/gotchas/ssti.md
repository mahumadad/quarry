# Gotchas: Server-Side Template Injection (SSTI)

## Common False Positives
- Client-side template rendering (AngularJS, Vue, Handlebars, Mustache in the browser): an arithmetic expression is evaluated by JavaScript in the victim's browser. That is client-side template injection (CSTI), which behaves like XSS, not server-side code execution. Different class, different impact, different severity.
- Pure reflection of the input: the page echoes what you sent (including braces or operators) without evaluating it. Reflection is not evaluation.
- Coincidental arithmetic: the number in the response already exists in the page (an ID, a price, a timestamp, a counter), or a different component computed it.
- Search or "preview" features that run an expression engine by design on a restricted, sandboxed grammar (spreadsheet-like formulas, pricing rules, Excel-style fields). Evaluation exists but is not a template engine with object access.
- Error messages that mention a template engine name because the input broke parsing in a logging or i18n layer, with no evaluation of attacker-controlled expressions.
- Output that is transformed by a WAF, CDN or edge worker (edge-side includes, edge templates) rather than the application server.
- Markdown, BBCode or rich-text renderers that expand syntax into HTML. This is content rendering, not template evaluation.
- A reflected value that is HTML-encoded and shown literally, with the "delimiters" visible in the output.
- Templates loaded from a trusted admin-only source (theme editor, email-template editor available only to administrators). Evaluate who can author the template before claiming exposure to unauthenticated users.

## Overclaim Traps
- "RCE via SSTI" reported after only observing an arithmetic result. Arithmetic evaluation proves expression evaluation, not code execution, file access or object traversal.
- Claiming engine identification (Jinja2, Twig, Freemarker, Velocity, etc.) from one ambiguous response. Several engines return the same result for the same simple probe; fingerprinting needs behavior that discriminates between engines.
- Rating as Critical when the engine runs in a hardened sandbox (restricted environment, allowlisted functions, no access to globals or the runtime). State what the sandbox actually permits.
- Extrapolating from a staging or demo template engine to production without confirming the same code path.
- Treating CSTI as SSTI to inflate severity. CSTI impact is bounded by the browser context; report it as XSS-class with its own proof.
- Claiming impact on other tenants or on the host without evidence of cross-boundary access.
- Reporting template syntax in user-generated content as a vuln when the platform stores it but never renders it through an engine.

## Minimum Proof Required
- Demonstrated server-side evaluation, not client-side: the evaluated result must be present in the raw HTTP response body (capture with a non-browser client such as curl or the proxy), with JavaScript execution ruled out. If the result only appears after the DOM renders, it is client-side.
- A control pair: the same request with a harmless literal returns the literal unchanged, and the request with the expression returns the evaluated value. Use a value that cannot appear coincidentally on the page.
- Server-side-only evidence that the browser cannot produce: for example, a value derived from server state or environment that the client could not compute. Record exactly what was read.
- Engine identification supported by at least one discriminating behavior, documented with the response.
- For any impact beyond evaluation (file read, command execution, environment access): a separate, minimal, non-destructive proof for each claim, approved by the operator before execution (see engagement gates). Do not escalate past the lowest-impact proof that establishes the claim.
- Request and response, timestamps and the exact injection point (parameter, header, field, template editor) recorded.
- Label the claim: Demonstrated (server-side evaluation shown), Inferred (evaluation seen, locus unclear), Unproven (reflection only).

## When to Mark N/A
- The application serves static content or a pure JSON API with no server-side templating and no user-controlled template source.
- User input is only ever passed as data to the template context (parameterized), never concatenated into template source, and probing confirms no evaluation.
- Rendering occurs only in the client with a framework configuration that does not evaluate expressions from user data.
- The only template-authoring surface is available to trusted administrators and is out of scope or by design (note it as a privilege-boundary observation, not SSTI).
- Target technology cannot be fingerprinted and no input reaches a rendering layer after reasonable coverage: mark "Not applicable - no evidence of server-side templating".
