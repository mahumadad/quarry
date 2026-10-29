#!/usr/bin/env python3
"""Measure reviewed Nuclei coverage against real vulnerable/secure lab stacks."""
from __future__ import annotations

import json
import shutil
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAB = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from engine.app_profile import AppProfile
from engine.artifacts import ArtifactStore
from engine.nuclei_runner import NucleiRunner
from engine.scope import Scope
from engine.timeguard import TimeWindowGuard


CASES = {
    "fastapi": {
        "ports": {"vulnerable": 18081, "secure": 18084},
        "stack": {"backend": ["python", "fastapi"], "frameworks": ["fastapi"]},
        "architecture": {"style": "monolith", "frontend_rendering": "spa"},
        "expected": {"fastapi-openapi-documentation", "python-environment-secret-exposed"},
    },
    "django": {
        "ports": {"vulnerable": 18082, "secure": 18085},
        "stack": {"backend": ["python", "django"], "frameworks": ["django"]},
        "architecture": {"style": "monolith", "frontend_rendering": "mpa"},
        "expected": {"django-admin-login-surface", "django-debug-exposed",
                     "python-environment-secret-exposed"},
    },
    "express": {
        "ports": {"vulnerable": 18083, "secure": 18086},
        "stack": {"backend": ["nodejs", "express"], "frameworks": ["express", "react"]},
        "architecture": {"style": "monolith", "frontend_rendering": "spa"},
        "expected": {"express-stack-trace-exposed", "node-environment-secret-exposed",
                     "node-package-metadata-exposed", "javascript-source-map-content-exposed"},
    },
}


def wait_ready(url: str, timeout: int = 90) -> None:
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return
        except Exception as exc:
            last_error = exc
            time.sleep(1)
    raise RuntimeError(f"Lab not ready: {url}: {last_error}")


def audit_for(target: str) -> Path:
    audit = LAB / ".runtime" / f"{target.rsplit(':', 1)[-1]}"
    audit.mkdir(parents=True, exist_ok=True)
    scope = Scope(authorization="isolated-local-lab-only")
    scope.add_in_scope("127.0.0.1", "ip")
    scope.save(audit / ".pentest-state" / "scope.json")
    TimeWindowGuard(audit).configure([], "UTC",
        (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat())
    return audit


def run_case(stack: str, mode: str, definition: dict) -> dict:
    target = f"http://127.0.0.1:{definition['ports'][mode]}"
    wait_ready(target + "/api/v1/health")
    app = AppProfile(target=target, tech_stack=definition["stack"], architecture=definition["architecture"])
    audit = audit_for(target)
    result = NucleiRunner(audit).run(target, app, f"LAB-{stack}-{mode}",
        rate_limit=2, concurrency=1, timeout=120)
    actual = {lead["template_id"] for lead in result["leads"]}
    expected = set(definition["expected"])
    false_negatives = sorted(expected - actual) if mode == "vulnerable" else []
    false_positives = sorted(actual) if mode == "secure" else []
    unexpected = sorted(actual - expected) if mode == "vulnerable" else []
    return {
        "stack": stack, "mode": mode, "target": target, "status": result["status"],
        "selected": sorted(item["id"] for item in result["selected"]),
        "expected": sorted(expected), "actual": sorted(actual),
        "false_negatives": false_negatives, "false_positives": false_positives,
        "unexpected_positive_leads": unexpected,
        "artifacts_intact": ArtifactStore(audit).verify()["intact"],
        "passed": result["status"] == "completed" and not false_negatives and not false_positives
                  and not unexpected and ArtifactStore(audit).verify()["intact"],
    }


def write_reports(results: list[dict]) -> None:
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": "loopback only",
        "cases": results,
        "passed": all(item["passed"] for item in results),
        "false_negatives": sum(len(item["false_negatives"]) for item in results),
        "false_positives": sum(len(item["false_positives"]) for item in results),
    }
    (LAB / "results.json").write_text(json.dumps(summary, indent=2) + "\n")
    lines = ["# Resultados del laboratorio Nuclei multistack", "",
             f"- Generado: {summary['generated_at']}",
             f"- Resultado global: **{'PASS' if summary['passed'] else 'FAIL'}**",
             f"- Falsos negativos: {summary['false_negatives']}",
             f"- Falsos positivos: {summary['false_positives']}", "",
             "| Stack | Modo | Esperados | Detectados | FN | FP | Inesperados | Artefactos |",
             "|---|---|---:|---:|---:|---:|---:|---|"]
    for item in results:
        lines.append(f"| {item['stack']} | {item['mode']} | {len(item['expected'])} | "
                     f"{len(item['actual'])} | {', '.join(item['false_negatives']) or '0'} | "
                     f"{', '.join(item['false_positives']) or '0'} | "
                     f"{', '.join(item['unexpected_positive_leads']) or '0'} | "
                     f"{'íntegros' if item['artifacts_intact'] else 'fallo'} |")
    lines += ["", "Los targets son exclusivamente loopback. Los valores sensibles son fixtures falsos.",
              "Cero leads en el modo seguro es un control de especificidad, no una prueba general de ausencia.", ""]
    (LAB / "results.md").write_text("\n".join(lines))


def main() -> int:
    if (LAB / ".runtime").exists():
        shutil.rmtree(LAB / ".runtime")
    results = [run_case(stack, mode, definition)
               for stack, definition in CASES.items() for mode in ("vulnerable", "secure")]
    write_reports(results)
    for item in results:
        print(f"{item['stack']:8} {item['mode']:10} {'PASS' if item['passed'] else 'FAIL'} "
              f"FN={item['false_negatives']} FP={item['false_positives']} "
              f"unexpected={item['unexpected_positive_leads']}")
    return 0 if all(item["passed"] for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
