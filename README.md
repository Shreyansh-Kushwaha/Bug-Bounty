# BugHunter — Autonomous AI Bug-Bounty Pipeline

A multi-agent pipeline that clones an **authorized** target repo, maps its attack
surface, forms ranked vulnerability hypotheses, writes and **sandbox-validates**
non-destructive proofs-of-concept, proposes **verified** patches, and drafts a
responsible-disclosure report — with a human-in-the-loop gate at every dangerous
step. Reports are written to disk and **never auto-submitted**.

```
Recon ─▶ Analyst ─▶ [gate] ─▶ Exploit (top-N) ─▶ [gate] ─▶ Patch ─▶ Verify ─▶ Report
```

## Safety model

- **Allowlist only.** Targets must be listed in `config/targets.json`; anything else is refused.
- **Cloned code only** — never run against live services.
- **Sandboxed PoCs.** Every PoC runs in a disposable Docker container: `--network none`,
  read-only rootfs, dropped capabilities, `no-new-privileges`, CPU/memory/pids limits, strict timeout.
- **Non-destructive PoCs.** The exploit agent must prove the primitive (e.g. print a sentinel);
  destructive or empty PoCs are refused before execution.
- **Human gates** before exploitation and before patch/report generation.
- **Tamper-evident audit log** (`data/audit.jsonl`) — a SHA-256 hash chain over every action.

## Install

```bash
make install          # creates .venv and installs requirements
cp .env.example .env  # add at least one provider key (Gemini free tier works)
```

Docker is required to *validate* PoCs and *verify* patches. Without it the pipeline
still generates every artifact and clearly reports that validation was skipped.

## Usage

```bash
python -m src.main list                          # show authorized targets
python -m src.main run pyyaml-old --yes           # full pipeline, auto-approve gates
python -m src.main run pyyaml-old --top-n 3 --parallel   # exploit top 3, concurrently
python -m src.main stage juice-shop analyst       # stop after a stage
python -m src.main recon dvwa                      # recon only
python -m src.main run pyyaml-old --resume         # reuse on-disk recon/analyst
python -m src.main diff pyyaml-old 3.11 3.12       # analyze only changed files
python -m src.main findings                         # list findings from SQLite
python -m src.main triage                           # duplicate findings across runs
python -m src.main dashboard -o report.html         # standalone HTML dashboard
python -m src.main audit verify                     # check the audit hash chain
```

### Run options

| Flag | Effect |
|------|--------|
| `--yes` | Auto-approve the human gates (never auto-submits a report) |
| `--top-n N` | Exploit the top N ranked hypotheses instead of just #1 |
| `--parallel` | Run hypotheses concurrently (thread pool) |
| `--resume` | Reuse existing `01_recon.json` / `02_analyst.json` artifacts |
| `--no-cache` | Disable the on-disk LLM response cache |

## Architecture

| Component | File | Role |
|-----------|------|------|
| Recon | `src/agents/recon.py` | Clone, tree/pattern scan, **Semgrep** dataflow scan → attack surface |
| Analyst | `src/agents/analyst.py` | Ranked vulnerability hypotheses grounded in real source lines |
| Exploit | `src/agents/exploit.py` | Non-destructive PoC + sandbox validation |
| Patch | `src/agents/patch.py` | Minimal fix (unified diff) + regression test |
| Verify | `src/sandbox/patch_verifier.py` | Proves the test fails before the patch and passes after |
| Report | `src/agents/report.py` | HackerOne-style report with CVSS 3.1 |
| Router | `src/models/router.py` | Multi-provider failover, caching, token/cost accounting |
| Sandbox | `src/sandbox/docker_runner.py` | Locked-down Docker execution |
| Store | `src/store/` | SQLite findings index, audit hash chain, HTML dashboard |

### Model providers

Providers are tried in order and fall through on rate-limits/errors:
**Gemini → Anthropic → Groq → OpenRouter → Ollama (local)**. Configure any subset
via `.env`. Every call records token usage and an estimated cost, printed as a
summary at the end of each run and appended to the audit log. Identical calls are
served from an on-disk cache (`data/cache/`), so re-runs are fast, cheap, and deterministic.

### Patch verification

`verify_patch` copies the repo into a throwaway dir, drops in the regression test,
runs it (expecting failure), applies the diff, and runs it again (expecting success).
Only when the test **fails before and passes after** is `patch_validated` set. If
test dependencies aren't available in the offline sandbox, it reports the patch as
*unverified* rather than claiming success. Set `PATCH_VERIFY_NETWORK=1` to allow
dependency installs during verification.

## Development

```bash
make test     # run the offline test suite (no network, no Docker, no API keys)
make lint     # byte-compile all modules
```

The test suite uses a `MockProvider` and monkeypatched sandbox, so the entire
pipeline is exercised end-to-end without any external dependency.

## Disclaimer

For authorized security research and education only. You are responsible for
ensuring you have permission to test any target. The tool refuses anything not on
the allowlist and never submits reports on your behalf.
