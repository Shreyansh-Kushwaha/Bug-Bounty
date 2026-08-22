"""Verify a proposed patch actually fixes the vulnerability.

Contract we check (the PatchAgent is told to satisfy exactly this):
  - The regression test FAILS on the unpatched tree (it catches the bug).
  - The regression test PASSES on the patched tree (the fix works).

Everything runs in the Docker sandbox against a disposable copy of the repo, so
the host tree is never modified. Degrades gracefully: if Docker is missing, the
diff won't apply, or test dependencies aren't available offline, it reports
`verified=False` with a clear reason rather than pretending success.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from src.sandbox.docker_runner import run_command_in_dir


@dataclass
class PatchVerification:
    verified: bool
    applied: bool
    before_failed: bool | None  # test failed on unpatched tree (as expected)
    after_passed: bool | None   # test passed on patched tree (as expected)
    reason: str
    before_output: str = ""
    after_output: str = ""


_DEP_MARKERS = ("no module named 'pytest'", "no module named pytest", "modulenotfounderror")


def _test_command(test_rel: str, language: str) -> list[str]:
    if language == "python":
        return ["python", "-m", "pytest", test_rel, "-q", "-p", "no:cacheprovider"]
    if language == "node":
        return ["node", test_rel]
    return ["sh", test_rel]


def _apply_diff(repo: Path, diffs: list[str]) -> bool:
    """Apply concatenated unified diffs to `repo`. Try git apply, then patch -p1/-p0."""
    combined = "\n".join(d if d.endswith("\n") else d + "\n" for d in diffs if d.strip())
    if not combined.strip():
        return False
    patch_file = repo / ".bughunter_patch.diff"
    patch_file.write_text(combined)
    attempts = [
        ["git", "-C", str(repo), "apply", "--recount", str(patch_file)],
        ["patch", "-p1", "-d", str(repo), "-i", str(patch_file), "--forward"],
        ["patch", "-p0", "-d", str(repo), "-i", str(patch_file), "--forward"],
    ]
    for cmd in attempts:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if r.returncode == 0:
            patch_file.unlink(missing_ok=True)
            return True
    patch_file.unlink(missing_ok=True)
    return False


def _looks_like_missing_deps(result) -> bool:
    blob = ((result.stdout or "") + (result.stderr or "")).lower()
    return any(m in blob for m in _DEP_MARKERS)


def verify_patch(
    clone_dir: Path,
    files_modified: list,          # list[FileEdit] with .path / .unified_diff
    regression_test_path: str,
    regression_test_code: str,
    language: str = "python",
) -> PatchVerification:
    if not clone_dir.exists():
        return PatchVerification(False, False, None, None, "Clone dir missing; cannot verify.")

    network = os.getenv("PATCH_VERIFY_NETWORK", "0") == "1"

    with tempfile.TemporaryDirectory(prefix="bughunter_verify_") as tmp:
        repo = Path(tmp) / "repo"
        shutil.copytree(clone_dir, repo, symlinks=True, ignore=shutil.ignore_patterns("node_modules", ".venv"))

        # Drop the regression test into the tree.
        test_abs = repo / regression_test_path
        test_abs.parent.mkdir(parents=True, exist_ok=True)
        test_abs.write_text(regression_test_code)

        cmd = _test_command(regression_test_path, language)

        before = run_command_in_dir(repo, cmd, language=language, network=network)
        if not before.executed:
            return PatchVerification(False, False, None, None,
                                     before.reason or "Sandbox unavailable for 'before' run.")
        if _looks_like_missing_deps(before):
            return PatchVerification(
                False, False, None, None,
                "Test dependencies unavailable in the offline sandbox "
                "(set PATCH_VERIFY_NETWORK=1 to allow installs).",
                before_output=(before.stdout + before.stderr)[-2000:],
            )
        before_failed = before.exit_code != 0

        applied = _apply_diff(repo, [f.unified_diff for f in files_modified])
        if not applied:
            return PatchVerification(
                False, False, before_failed, None,
                "Patch did not apply cleanly (git apply / patch both failed).",
                before_output=(before.stdout + before.stderr)[-2000:],
            )

        after = run_command_in_dir(repo, cmd, language=language, network=network)
        after_passed = after.executed and after.exit_code == 0

        verified = bool(before_failed) and bool(after_passed)
        if verified:
            reason = "Regression test fails before the patch and passes after — fix confirmed."
        elif not before_failed:
            reason = "Regression test did NOT fail on the unpatched tree; it may not exercise the bug."
        else:
            reason = "Regression test still fails after applying the patch; fix is incomplete."

        return PatchVerification(
            verified=verified, applied=True,
            before_failed=before_failed, after_passed=after_passed, reason=reason,
            before_output=(before.stdout + before.stderr)[-2000:],
            after_output=(after.stdout + after.stderr)[-2000:],
        )
