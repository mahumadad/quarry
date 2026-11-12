"""Multi-step stateful workflow engine for business-logic attacks.

Purpose: business-logic abuse (negative quantities, price manipulation, coupon
reuse, step skipping, race-prone checkouts) always involves an ordered
sequence of stateful requests where later steps consume values produced by
earlier ones (basket ids, order tokens, CSRF nonces). Manual exploitation
dies on exactly that mechanical friction. This engine:

  1. executes a declarative flow (JSON) of HTTP steps against a target,
  2. extracts variables from each response and feeds them into later steps
     ({{var}} templating in url / headers / body),
  3. applies operator-defined mutations to any step (the attack),
  4. checks invariants on the resulting state (negative total, double-spend,
     skipped step) — an invariant violation observed in the transcript is
     Demonstrated evidence; absence is an honest negative.

Flow files live anywhere; transcripts (full request/response evidence) are
written to <audit-dir>/.pentest-state/workflows/.

CLI:
  python3 -m engine.workflows run flow.json --audit-dir .
  python3 -m engine.workflows run flow.json --audit-dir . \
      --set 'add-item.json.quantity=-100' --set 'checkout.json.addressId=1'
"""

import argparse
import copy
import json
import re
import sys
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

try:
    from .http_client import ProtectedHTTPClient
    from .redaction import redact
    from .storage import atomic_write_json
except ImportError:
    from http_client import ProtectedHTTPClient
    from redaction import redact
    from storage import atomic_write_json

TEMPLATE_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}")


# ---- flow model ----

@dataclass
class StepResult:
    name: str
    method: str
    url: str
    request_body: str = ""
    status: int = 0
    response_body: str = ""
    duration_ms: float = 0.0
    error: str = ""


@dataclass
class InvariantResult:
    name: str
    check: str
    step: str
    violated: bool = False
    observed: str = ""
    detail: str = ""


@dataclass
class RunTranscript:
    flow: str
    started_at: str = ""
    base_url: str = ""
    steps: list = field(default_factory=list)          # StepResult dicts
    extracted_vars: dict = field(default_factory=dict)
    invariants: list = field(default_factory=list)     # InvariantResult dicts
    mutations_applied: list = field(default_factory=list)
    any_invariant_violated: bool = False

    def __post_init__(self):
        if not self.started_at:
            self.started_at = datetime.now(timezone.utc).isoformat()


# ---- templating / extraction ----

def render(value, variables: dict):
    """Recursively substitute {{var}} in strings (url, headers, json body)."""
    if isinstance(value, str):
        def repl(m):
            return str(variables.get(m.group(1), m.group(0)))
        return TEMPLATE_RE.sub(repl, value)
    if isinstance(value, dict):
        return {k: render(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [render(v, variables) for v in value]
    return value


def extract_path(data, path: str):
    """Dotted-path lookup into parsed JSON ('authentication.token', 'data.id')."""
    cur = data
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return None
    return cur


def extract_all(data, path: str) -> list:
    """Like extract_path but a '*' segment iterates a list and returns all
    matching values ('data.*.totalPrice' -> [1.99, -196.02])."""
    parts = path.split(".")
    results = []
    def walk(cur, i):
        if i == len(parts):
            results.append(cur)
            return
        part = parts[i]
        if part == "*" and isinstance(cur, list):
            for item in cur:
                walk(item, i + 1)
        elif isinstance(cur, dict) and part in cur:
            walk(cur[part], i + 1)
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            walk(cur[int(part)], i + 1)
    walk(data, 0)
    return results


# ---- runner ----

class WorkflowRunner:
    def __init__(self, flow: dict, audit_dir: str = ".", run_id: str = "workflow",
                 approved_digest: str = ""):
        self.flow = flow
        self.base_url = (flow.get("base_url") or "").rstrip("/")
        self.variables = dict(flow.get("vars") or {})
        self.audit_dir = Path(audit_dir)
        self.run_id = run_id
        self.approved_digest = approved_digest
        self.http = ProtectedHTTPClient(audit_dir)
        self.transcript = RunTranscript(flow=flow.get("name", "unnamed"),
                                        base_url=self.base_url)

    def apply_mutations(self, mutations: list[str]):
        """Apply 'step.key=value' mutations. key path supports .json.<path>,
        .headers.<name>, .url. value is parsed as JSON when possible."""
        steps = {s.get("name"): s for s in self.flow.get("steps", [])}
        for mut in mutations:
            step_name, _, keypath = mut.partition(".")
            key, _, raw = keypath.partition("=")
            step = steps.get(step_name)
            if step is None:
                raise KeyError(f"mutation targets unknown step '{step_name}'")
            try:
                value = json.loads(raw)
            except json.JSONDecodeError:
                value = raw
            parts = key.split(".")
            if parts[0] in ("json", "headers", "params"):
                container = step.setdefault(parts[0], {})
                for p in parts[1:-1]:
                    container = container.setdefault(p, {})
                container[parts[-1]] = value
            elif parts[0] in ("url", "method"):
                step[parts[0]] = value
            else:
                raise KeyError(f"unsupported mutation key '{key}'")
            self.transcript.mutations_applied.append(mut)

    def _do_request(self, step: dict) -> StepResult:
        name = step.get("name", "step")
        url = self.base_url + render(step.get("url", ""), self.variables)
        params = render(step.get("params") or {}, self.variables)
        if params:
            from urllib.parse import urlencode
            url += ("&" if "?" in url else "?") + urlencode(params)
        headers = render(step.get("headers") or {}, self.variables)
        body = None
        if "json" in step:
            headers.setdefault("Content-Type", "application/json")
            body = json.dumps(render(step["json"], self.variables)).encode()
        elif "data" in step:
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            from urllib.parse import urlencode
            body = urlencode(render(step["data"], self.variables)).encode()
        result = StepResult(name=name, method=step.get("method", "GET"), url=url,
                            request_body=body.decode(errors="replace") if body else "")
        start = time.time()
        response = self.http.request(result.method, url, headers=headers, body=body,
            timeout=15, dangerous=bool(step.get("dangerous") or self.flow.get("dangerous")),
            approved_digest=self.approved_digest, run_id=self.run_id, task_id=name)
        result.status = response["status"]
        result.error = response["error"]
        # Keep the full in-memory body for invariants; _save bounds the JSON view.
        result.response_body = response["body"].decode(errors="replace")
        result.duration_ms = round((time.time() - start) * 1000, 1)
        return result

    def run(self) -> RunTranscript:
        t = self.transcript
        for step in self.flow.get("steps", []):
            r = self._do_request(step)
            t.steps.append(asdict(r))
            # variable extraction from this step's response
            try:
                parsed = json.loads(r.response_body)
            except json.JSONDecodeError:
                parsed = None
            if parsed is not None:
                for var, path in (step.get("extract") or {}).items():
                    val = extract_path(parsed, path)
                    if val is not None:
                        self.variables[var] = val
            if r.error:
                break  # don't march on with a broken chain
        t.extracted_vars = {k: v for k, v in self.variables.items()
                            if k not in (self.flow.get("vars") or {})}
        t.invariants = [asdict(self.check_invariant(inv))
                        for inv in self.flow.get("invariants", [])]
        t.any_invariant_violated = any(i["violated"] for i in t.invariants)
        self._save()
        return t

    # ---- invariants ----

    def check_invariant(self, inv: dict) -> InvariantResult:
        """An invariant VIOLATION is the finding: business rule broken.
        Checks: json_lt / json_gt / json_eq (numeric or string) against a
        step's response JSON path; contains / not_contains on the raw body;
        status_is on the step's HTTP status."""
        res = InvariantResult(name=inv.get("name", "invariant"),
                              check=inv.get("check", ""),
                              step=inv.get("step", ""))
        step_rec = next((s for s in self.transcript.steps
                         if s["name"] == res.step), None)
        if step_rec is None:
            res.detail = "step not executed"
            return res
        body = step_rec["response_body"]
        check = res.check
        if check in ("json_lt", "json_gt", "json_eq", "json_any_lt", "json_any_gt", "json_any_eq"):
            try:
                parsed_body = json.loads(body)
            except json.JSONDecodeError:
                parsed_body = None
            path = inv.get("path", "")
            target = inv.get("value")
            if check.startswith("json_any_") or (parsed_body is not None and ".*" in f".{path}"):
                values = extract_all(parsed_body, path) if parsed_body is not None else []
                res.observed = str(values[:5])
                if not values:
                    res.detail = f"path '{path}' matched nothing"
                    return res
                op = check.replace("json_any_", "").replace("json_", "")
                if op == "lt":
                    res.violated = any(float(v) < float(target) for v in values)
                elif op == "gt":
                    res.violated = any(float(v) > float(target) for v in values)
                else:
                    res.violated = any(str(v) == str(target) for v in values)
            else:
                observed = extract_path(parsed_body, path) if parsed_body is not None else None
                res.observed = str(observed)
                if observed is None:
                    res.detail = f"path '{path}' not found"
                elif check == "json_lt":
                    res.violated = float(observed) < float(target)
                elif check == "json_gt":
                    res.violated = float(observed) > float(target)
                else:
                    res.violated = str(observed) == str(target)
        elif check in ("contains", "not_contains"):
            needle = str(inv.get("value", ""))
            res.observed = body[:300]
            res.violated = (needle in body) if check == "contains" \
                else (needle not in body)
        elif check == "status_is":
            res.observed = str(step_rec["status"])
            res.violated = step_rec["status"] == int(inv.get("value", 0))
        res.detail = res.detail or ("VIOLATED" if res.violated else "holds")
        return res

    def _save(self):
        out_dir = self.audit_dir / ".pentest-state" / "workflows"
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe = re.sub(r"[^a-zA-Z0-9-]", "-", self.transcript.flow)
        view = redact(asdict(self.transcript))
        for step in view["steps"]:
            for field_name in ("request_body", "response_body"):
                if len(step[field_name]) > 5000:
                    step[field_name] = step[field_name][:5000] + "\n[VIEW TRUNCATED — full artifact in raw/]"
        atomic_write_json(out_dir / f"{safe}-{ts}.json", view)


def load_flow(path: str) -> dict:
    return json.loads(Path(path).read_text())


def main() -> int:
    ap = argparse.ArgumentParser(prog="engine.workflows")
    ap.add_argument("cmd", choices=["run"])
    ap.add_argument("flow", help="flow JSON file")
    ap.add_argument("--audit-dir", default=".")
    ap.add_argument("--set", dest="mutations", action="append", default=[],
                    metavar="STEP.KEY=VALUE",
                    help="mutate a step before running (repeatable); "
                         "keys: json.<path>, headers.<name>, params.<name>, url, method")
    args = ap.parse_args()

    flow = load_flow(args.flow)
    runner = WorkflowRunner(flow, audit_dir=args.audit_dir)
    try:
        runner.apply_mutations(args.mutations)
    except KeyError as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        return 1
    t = runner.run()
    out = asdict(t)
    out["ok"] = True
    print(json.dumps(out, indent=2, ensure_ascii=False))
    # exit code doubles as the attack signal for toolrunner chains
    return 0 if t.any_invariant_violated else 1


if __name__ == "__main__":
    sys.exit(main())
