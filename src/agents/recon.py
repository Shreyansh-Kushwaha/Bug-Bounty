"""Recon agent: clones a target repo and maps its attack surface.

Produces a JSON map that later agents (Analyst) consume.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from pydantic import BaseModel, Field

from src.agents.base import Agent
from src.models.router import Tier


class ReconInput(BaseModel):
    target_name: str
    repo_url: str
    ref: str = "main"
    clone_dir: Path


class RiskyFile(BaseModel):
    path: str
    reason: str
    risk_level: str = Field(description="low | medium | high")
    cwe_hints: list[str] = Field(default_factory=list)


class ReconOutput(BaseModel):
    target: str
    entry_points: list[str] = Field(description="Files that handle external input")
    risky_files: list[RiskyFile]
    dependencies: list[str] = Field(default_factory=list)
    summary: str


SUSPICIOUS_PATTERNS = [
    ("yaml.load", "unsafe YAML deserialization"),
    ("pickle.load", "pickle deserialization RCE"),
    ("eval(", "dynamic eval"),
    ("exec(", "dynamic exec"),
    ("subprocess.", "command execution"),
    ("os.system", "shell execution"),
    ("shell=True", "shell injection risk"),
    ("innerHTML", "DOM XSS sink"),
    ("dangerouslySetInnerHTML", "React XSS sink"),
    ("SELECT * FROM", "raw SQL"),
    ("md5(", "weak crypto"),
    ("sha1(", "weak crypto"),
    ("random.random", "insecure randomness in security context"),
]


class ReconAgent(Agent[ReconInput, ReconOutput]):
    name = "Recon"
    tier = Tier.FAST

    def system_prompt(self) -> str:
        return (
            "You are a security reconnaissance agent. Given a repository tree and "
            "grep hits for suspicious patterns, identify entry points, high-risk files, "
            "and rank them. Output ONLY valid JSON matching the schema — no prose."
        )

    def build_prompt(self, inp: ReconInput) -> str:
        tree = self._tree(inp.clone_dir)
        hits = self._grep_patterns(inp.clone_dir)
        deps = self._detect_deps(inp.clone_dir)

        return f"""Target: {inp.target_name} ({inp.repo_url} @ {inp.ref})

Repository tree (truncated):
{tree[:4000]}

Pattern scan hits:
{hits[:4000]}

Declared dependencies:
{deps[:1500]}

Produce JSON with this exact shape:
{{
  "target": "{inp.target_name}",
  "entry_points": ["path1", "path2"],
  "risky_files": [
    {{"path": "...", "reason": "...", "risk_level": "high|medium|low", "cwe_hints": ["CWE-502"]}}
  ],
  "dependencies": ["dep1", "dep2"],
  "summary": "2-3 sentence overview of the attack surface"
}}
"""

    def output_model(self) -> type[ReconOutput]:
        return ReconOutput

    @staticmethod
    def clone(repo_url: str, ref: str, dest: Path) -> None:
        # Always capture output: git writes progress to stderr, and inheriting
        # the worker thread's pipe causes SIGPIPE when the parent closes it.
        if dest.exists() and (dest / ".git").exists():
            subprocess.run(
                ["git", "-C", str(dest), "fetch", "--depth", "1", "origin", ref],
                check=False, capture_output=True, text=True,
            )
            subprocess.run(
                ["git", "-C", str(dest), "checkout", ref],
                check=False, capture_output=True, text=True,
            )
            return

        dest.parent.mkdir(parents=True, exist_ok=True)

        # Try the requested ref first. If the remote doesn't have that branch,
        # fall back to whatever the default branch is (handles main vs master).
        r = subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", ref, repo_url, str(dest)],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            return

        err = (r.stderr or "") + (r.stdout or "")
        if "Remote branch" in err and "not found" in err:
            # Wipe the partial clone if any, then try the default branch.
            if dest.exists():
                import shutil
                shutil.rmtree(dest, ignore_errors=True)
            r2 = subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, str(dest)],
                capture_output=True, text=True,
            )
            if r2.returncode == 0:
                return
            raise RuntimeError(
                f"git clone failed for {repo_url} (also tried default branch): "
                f"{(r2.stderr or r2.stdout or '').strip()[:300]}"
            )
        raise RuntimeError(
            f"git clone failed for {repo_url}@{ref}: {err.strip()[:300]}"
        )

    @staticmethod
    def _tree(root: Path, max_entries: int = 200) -> str:
        skip_dirs = {".git", "node_modules", "__pycache__", "dist", "build", ".venv", "venv"}
        lines = []
        count = 0
        for path in sorted(root.rglob("*")):
            if any(part in skip_dirs for part in path.parts):
                continue
            if path.is_file():
                lines.append(str(path.relative_to(root)))
                count += 1
                if count >= max_entries:
                    lines.append(f"... ({count}+ files truncated)")
                    break
        return "\n".join(lines)

    @staticmethod
    def _grep_patterns(root: Path) -> str:
        skip_dirs = {".git", "node_modules", "__pycache__", "dist", "build", ".venv", "venv"}
        hits = []
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix not in {".py", ".js", ".ts", ".tsx", ".java", ".rb", ".go", ".php"}:
                continue
            if any(part in skip_dirs for part in path.parts):
                continue
            try:
                text = path.read_text(errors="ignore")
            except (OSError, UnicodeDecodeError):
                continue
            for pattern, reason in SUSPICIOUS_PATTERNS:
                if pattern in text:
                    for lineno, line in enumerate(text.splitlines(), 1):
                        if pattern in line:
                            hits.append(f"{path.relative_to(root)}:{lineno} [{reason}] {line.strip()[:120]}")
                            break
        return "\n".join(hits[:200])

    @staticmethod
    def _detect_deps(root: Path) -> str:
        candidates = [
            "requirements.txt", "pyproject.toml", "Pipfile",
            "package.json", "go.mod", "Cargo.toml", "composer.json",
        ]
        out = []
        for name in candidates:
            f = root / name
            if f.exists():
                out.append(f"--- {name} ---")
                out.append(f.read_text(errors="ignore")[:800])
        return "\n".join(out)
