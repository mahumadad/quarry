"""Deliverable packaging: manifest + bundle + optional encryption.

What ships to the client must be exactly what was attested: this module
builds a SHA-256 manifest over every artifact (report, findings, evidence,
exports, custody log) and bundles it for delivery. Tampering after packaging
is detectable by re-verifying the manifest — complements custody.py (which
covers the process) with integrity of the final package (which covers the
product).

Encryption is optional via gpg (symmetric or recipient-based) when available;
the manifest works with or without it.
"""

import hashlib
import json
import shutil
import subprocess
import tarfile
from datetime import datetime, timezone
from pathlib import Path

from .storage import atomic_write_json


EXCLUDE_PATTERNS = {".DS_Store", "__pycache__"}
EXCLUDE_FILES = {"manifest.json", "vault.json", "vault.key"}


def hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(deliverable_dir: str) -> dict:
    """SHA-256 of every file under the deliverable dir."""
    root = Path(deliverable_dir)
    files = {}
    for p in sorted(root.rglob("*")):
        if p.is_symlink():
            continue
        if (p.is_file() and p.name not in EXCLUDE_FILES
                and not any(x in p.parts for x in EXCLUDE_PATTERNS)):
            files[str(p.relative_to(root))] = {
                "sha256": hash_file(p),
                "bytes": p.stat().st_size,
            }
    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "root": str(root),
        "file_count": len(files),
        "files": files,
    }
    manifest_path = root / "manifest.json"
    manifest["manifest_sha256"] = hashlib.sha256(
        json.dumps(files, sort_keys=True).encode()
    ).hexdigest()
    atomic_write_json(manifest_path, manifest)
    return manifest


def verify_manifest(deliverable_dir: str) -> dict:
    root = Path(deliverable_dir)
    manifest = json.loads((root / "manifest.json").read_text())
    missing, altered = [], []
    for rel, meta in manifest["files"].items():
        p = root / rel
        if not p.exists():
            missing.append(rel)
        elif hash_file(p) != meta["sha256"]:
            altered.append(rel)
    return {
        "intact": not missing and not altered,
        "missing": missing,
        "altered": altered,
        "file_count": manifest["file_count"],
        "manifest_sha256": manifest.get("manifest_sha256"),
    }


def bundle(deliverable_dir: str, out_path: str,
           gpg_recipient: str = "", gpg_symmetric: bool = False) -> dict:
    """Create a bundle containing exactly the attested files, never excluded secrets."""
    root = Path(deliverable_dir)
    manifest = build_manifest(str(root))

    tar_path = Path(out_path)
    tar_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tar_path, "w:gz") as tar:
        for relative in sorted(manifest["files"]):
            tar.add(root / relative, arcname=f"{root.name}/{relative}", recursive=False)
        tar.add(root / "manifest.json", arcname=f"{root.name}/manifest.json", recursive=False)

    verification = verify_manifest(str(root))
    if not verification["intact"]:
        raise RuntimeError(f"Deliverable changed while bundling: {verification}")
    result = {"bundle": str(tar_path), "bundle_sha256": hash_file(tar_path),
              "encrypted": False, "manifest_verified": True}

    if (gpg_recipient or gpg_symmetric) and shutil.which("gpg"):
        gpg_path = tar_path.with_suffix(tar_path.suffix + ".gpg")
        cmd = ["gpg", "--output", str(gpg_path), "--yes"]
        if gpg_symmetric:
            cmd += ["--symmetric", "--cipher-algo", "AES256"]
        else:
            cmd += ["--encrypt", "--recipient", gpg_recipient]
        cmd += [str(tar_path)]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode == 0:
            result["encrypted"] = True
            result["encrypted_bundle"] = str(gpg_path)
        else:
            raise RuntimeError(f"Requested encryption failed; bundle not deliverable: {proc.stderr.strip()}")
    elif gpg_recipient or gpg_symmetric:
        raise RuntimeError("Requested encryption but gpg is unavailable; bundle not deliverable")

    return result
