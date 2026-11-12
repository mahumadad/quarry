"""C1 regression: every workflow YAML must parse with stdlib yaml.safe_load.

Catches unquoted YAML aliases like `- *` that crash the loader.
"""
import pathlib
import yaml
import pytest

WORKFLOWS_DIR = pathlib.Path(__file__).resolve().parent.parent / "workflows"


def _workflow_files():
    return sorted(WORKFLOWS_DIR.glob("*.yaml"))


@pytest.fixture(params=_workflow_files(), ids=lambda p: p.name)
def workflow_path(request):
    return request.param


def test_workflow_parses(workflow_path):
    text = workflow_path.read_text(encoding="utf-8")
    result = yaml.safe_load(text)
    assert isinstance(result, dict), f"{workflow_path.name} did not parse as a mapping"
    assert "phases" in result or "name" in result, (
        f"{workflow_path.name} missing expected top-level keys"
    )
