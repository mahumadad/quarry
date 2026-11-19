"""Anti-fabrication wiring guard.

A module documented as a capability but called by nothing outside tests is a
claim without an implementation path (three_gate was exactly that before this
work). These tests fail if the keystone verification/recon/execution modules
lose their real callers, so the docs can't drift back to fiction.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

ENGINE = ROOT / "engine"


def _src(name: str) -> str:
    return (ENGINE / name).read_text(encoding="utf-8")


def test_three_gate_has_callers_and_cli():
    # The verification gate must be reachable from the execution path AND a CLI,
    # not sit unused like it did before.
    assert "verify_and_record" in _src("executor.py")
    assert "verify_and_record" in _src("chain_exploit.py")
    tg = _src("three_gate.py")
    assert "def main(" in tg and "verify_and_record" in tg


def test_fanout_is_gated_and_reachable():
    fo = _src("fanout.py")
    assert "command_policy" in fo       # scope gate present
    assert "def main(" in fo            # reachable as a CLI


def test_reference_executor_wired_into_orchestrator():
    orch = _src("orchestrator.py")
    assert "ReferenceExecutor" in orch
    assert '"run"' in orch or "'run'" in orch  # run subcommand exists


def test_chain_execution_loop_present():
    ce = _src("chain_exploit.py")
    assert "def execute_chain(" in ce
    assert "def main(" in ce


def test_llm_judge_present_in_bridge():
    art = _src("ai_red_team.py")
    assert "def judge_response(" in art
    assert "def classify_response_dual(" in art
