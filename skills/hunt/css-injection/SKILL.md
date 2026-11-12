---
name: css-injection
description: >
  Test confirmed style/markup sinks for CSS-based data exposure or UI manipulation when
  script execution is not required. Use after mapping a CSS/HTML injection sink; do not
  relabel ordinary missing CSP or self-only styling as a finding. Keywords: CSS injection,
  attribute selector exfiltration, style injection, CSS data leak.
metadata:
  type: hunt
  phase: hunting
  tools: [browser, curl, oast]
depends_on: [scope-discipline, session-context]
feeds_into: [finding-validation, chain-custom]
---

## Prerequisites

- A specific attacker-controlled value reaches a style block, stylesheet, `style` attribute,
  or CSS-aware renderer. Preserve the exact sink and identity.
- Authorization for any callback/OAST infrastructure and for state-changing test fixtures.
- A unique canary in your own test account; never target another user's secrets.

## Methodology

1. **Confirm the sink without assuming XSS.** Inject benign CSS with a unique marker and
   verify where it lands, which sanitization applies, and whether other users can view it.
   If script execution is possible, route the XSS hypothesis to `xss` instead of double-reporting.
2. **Measure impact classes separately:** UI redress or hidden controls; cross-origin resource
   loads; CSS selector-based inference of sensitive attributes; font/import/parser behavior.
   A visual defacement alone is not evidence of secret extraction.
3. **For selector-based inference,** use only a canary attribute you created. Compare a matching
   and a non-matching selector in the same browser and identity. Observe the resulting request
   at an authorized callback; repeat with shuffled negative controls to rule out prefetching,
   caching, and browser URL normalization.
4. **Test delivery boundaries.** Establish who must view the page, whether the sink is stored or
   reflected, whether CSS is sanitized on each render, and whether the callback actually reveals
   information not already public. Check `@import` and font restrictions without assuming they
   are universally exploitable.
5. **Record coverage precisely.** Sink, selector technique, browser, identity, canary ID, request
   artifact and callback artifact belong in the same coverage cell. Browser incompatibility or
   blocked callbacks is `inconclusive`/`blocked`, not `tested_clean`.

## Evidence and dedup

- Show source → CSS sink → victim/view boundary → observable security impact.
- Include full relevant markup, computed style evidence and matched/unmatched controls.
- Link to an HTML/XSS finding when both share one sink and one remediation; do not create two
  findings for the same root cause merely because CSS and JS impacts were both demonstrated.

## N/A and gotchas

- Static CSS editing in your own developer tools is not injection.
- A callback generated unconditionally by the browser proves a request, not data leakage.
- Attribute-selector techniques cannot read arbitrary text nodes or every kind of secret; state
  exactly what was inferred. DoS through pathological CSS is out of scope unless explicitly allowed.
