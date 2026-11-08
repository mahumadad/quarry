"""C4 regression: ArtifactStore must produce unique IDs and never overwrite.

Two captures with identical run_id/task_id/kind must get different artifact_ids
and different file paths — the old content-derived ID allowed silent overwrites.
"""
import json
import pathlib
import sys
import pytest

ENGINE = pathlib.Path(__file__).resolve().parent.parent / "engine"
sys.path.insert(0, str(ENGINE))

from artifacts import ArtifactStore  # noqa: E402


@pytest.fixture()
def store(tmp_path):
    audit_dir = tmp_path / "engagement"
    state = audit_dir / ".pentest-state"
    state.mkdir(parents=True)
    (state / "artifacts.json").write_text(json.dumps({"artifacts": []}))
    return ArtifactStore(audit_dir)


def test_same_inputs_different_ids(store):
    """Two captures with identical run/task/kind must produce different IDs."""
    a = store.capture("manual", "http", "request", "GET /api/v1/users HTTP/1.1")
    b = store.capture("manual", "http", "request", "GET /api/v1/orders HTTP/1.1")
    assert a.artifact_id != b.artifact_id, "Artifact IDs must be unique per capture"


def test_same_inputs_different_paths(store):
    """Two captures with identical run/task/kind must produce different paths."""
    a = store.capture("manual", "http", "request", "content-a")
    b = store.capture("manual", "http", "request", "content-b")
    assert a.path != b.path, "Artifact paths must be unique per capture"


def test_both_files_exist(store):
    """Both artifacts must be persisted — no silent overwrite."""
    a = store.capture("manual", "http", "response", b"HTTP/1.1 200 OK\r\n\r\nbody-a")
    b = store.capture("manual", "http", "response", b"HTTP/1.1 200 OK\r\n\r\nbody-b")
    path_a = store.root / a.path
    path_b = store.root / b.path
    assert path_a.exists(), f"First artifact file missing: {a.path}"
    assert path_b.exists(), f"Second artifact file missing: {b.path}"
    assert path_a.read_bytes() != path_b.read_bytes(), "Files must contain different content"


def test_identical_content_still_unique(store):
    """Even identical content must produce distinct artifacts."""
    content = "GET / HTTP/1.1\r\nHost: target.example.com\r\n\r\n"
    a = store.capture("run1", "task1", "request", content)
    b = store.capture("run1", "task1", "request", content)
    assert a.artifact_id != b.artifact_id
    assert a.path != b.path
    assert a.sha256 == b.sha256, "Content hash should match for identical content"


def test_index_contains_both(store):
    """The artifact index must list both captures, not just the latest."""
    store.capture("manual", "http", "request", "first")
    store.capture("manual", "http", "request", "second")
    records = store.list()
    assert len(records) == 2, f"Expected 2 artifacts in index, got {len(records)}"


def test_verify_intact(store):
    """Freshly captured artifacts must pass integrity verification."""
    store.capture("run", "task", "evidence", "proof of concept output")
    result = store.verify()
    assert result["intact"] is True
    assert result["missing"] == []
    assert result["altered"] == []
