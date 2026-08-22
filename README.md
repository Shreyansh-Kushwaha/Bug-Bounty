# BugHunter — Autonomous AI Bug-Bounty Pipeline

An automated security research platform that chains AI agents to identify,
validate, and patch vulnerabilities in **authorized** repositories, and
produces structured HackerOne-style reports ready for human review before
any disclosure. A web UI (React + FastAPI) sits on top of the same CLI
pipeline for interactive runs, live logs, and a security scorecard.

```
Recon ──▶ scanners (secrets/deps) ──▶ Analyst ──▶ roadmap ──▶ [gate]
      ──▶ Exploit (top-N) ──▶ [gate] ──▶ Patch ──▶ Verify ──▶ Report ──▶ score
```

Human confirmation gates sit before Exploit and before Patch/Report. The
report is written to disk and **never auto-submitted**.

---

## Table of Contents

1. [What It Does](#what-it-does)
2. [Pipeline Stages](#pipeline-stages)
3. [Architecture](#architecture)
4. [Tech Stack](#tech-stack)
5. [Project Structure](#project-structure)
6. [Setup](#setup)
7. [Running](#running)
8. [Web UI](#web-ui)
9. [Configuration](#configuration)
10. [Output Artifacts](#output-artifacts)
11. [Safety Design](#safety-design)
12. [Limitations](#limitations)
13. [Environment Notes (Replit/Nix)](#environment-notes-replitnix)
14. [Development](#development)

---

## What It Does

Given a target repository listed in the authorization allowlist (or
self-attested through the web UI), the pipeline:

1. **Scans** the repo for risky code patterns — grep heuristics plus a **Semgrep**
   dataflow-aware pass — and runs deterministic **secrets** and **dependency-CVE**
   scanners alongside it.
2. **Analyzes** findings with an LLM to form ranked vulnerability hypotheses with
   CWE classification, and builds a prioritized **fix roadmap** across code,
   secrets, and dependency findings.
3. **Generates** a non-destructive proof-of-concept (PoC) for the **top N**
   hypotheses (configurable, optionally in parallel).
4. **Executes** each PoC in an isolated Docker sandbox to validate it (if Docker
   is available; the pipeline still completes without it).
5. **Proposes** a minimal patch with a regression test, then **verifies** the fix
   in the sandbox — the test must fail before the patch and pass after.
6. **Drafts** a responsible-disclosure report (HackerOne format, CVSS score)
   plus a plain-English ("ELI5") variant, and computes a per-category
   **security score** (0–100, A–F grade).

---

## Pipeline Stages

```
Repo Clone
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  Stage 1: Recon + Scanners                           │
│  • Clones repo at pinned ref (falls back to the      │
│    default branch if the pinned ref is missing)      │
│  • grep + Semgrep patterns for risky sinks           │
│  • Deterministic secrets scan (regex, high-conf.)    │
│  • Dependency CVE scan (osv-scanner/pip-audit/npm)   │
└───────────────────────┬─────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│  Stage 2: Analyst + Roadmap                          │
│  • LLM reads risky files and source context          │
│  • Forms ranked vulnerability hypotheses              │
│  • Roadmap: code + secrets + deps, priority-ordered   │
└───────────────────────┬─────────────────────────────┘
                         │
                [HUMAN GATE: proceed?]
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│  Stage 3: Exploit (top-N, optionally parallel)       │
│  • LLM writes a non-destructive PoC per hypothesis    │
│  • Executed in a Docker sandbox (if available)        │
│  • Validates by checking stdout for a sentinel string │
└───────────────────────┬─────────────────────────────┘
                         │
                [HUMAN GATE: generate patches?]
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│  Stage 4: Patch + Verify                             │
│  • LLM proposes the minimal secure fix + a test       │
│  • Verifier applies the diff in the sandbox and       │
│    confirms: test fails before, passes after          │
└───────────────────────┬─────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│  Stage 5: Report + Score                             │
│  • HackerOne-style report + CVSS vector/score         │
│  • Plain-English ("ELI5") variant                     │
│  • Per-category security score (0–100, A–F)           │
│  • Saved as Markdown/JSON — never auto-submitted      │
└─────────────────────────────────────────────────────┘
```

---

## Architecture

### Agent Pattern

Every LLM-driven pipeline stage is a typed agent inheriting from
`Agent[TInput, TOutput]` in `src/agents/base.py`:

```python
class Agent(ABC, Generic[TInput, TOutput]):
    def system_prompt(self) -> str: ...      # LLM instruction
    def build_prompt(self, inp) -> str: ...  # formats input → prompt
    def output_model(self) -> type[TOutput]: # Pydantic model for JSON validation
    def run(self, inp) -> TOutput: ...       # calls router → parses JSON → validates
```

Each agent calls the `ModelRouter`, extracts JSON from the response (fenced or
raw), repairs it with the `json-repair` library and, failing that, a one-shot
reprompt asking the model to return valid JSON, then validates the result
against a Pydantic model.

### LLM Router (`src/models/router.py`)

`ModelRouter` tries providers in order and falls through on rate-limits/errors:
**Gemini → Anthropic → Groq → OpenRouter → Ollama (local)**. Within Gemini,
models are tried in a fallback chain (`gemini-3-flash-preview` →
`gemini-2.5-flash` → `gemini-2.5-flash-lite`) on 429/503/overload. Every call
records token usage, an estimated cost, and a persistent per-run usage row
(`src/store/usage.py`) for quota/cost tracking. Identical calls are served from
an on-disk cache (`data/cache/`) so re-runs are fast, cheap, and deterministic.

| Tier | Used By |
|------|---------|
| `FAST` | Recon, Report |
| `REASONING` | Analyst |
| `CODER` | Exploit, Patch |

### Orchestrator (`src/orchestrator.py`)

`RunContext` carries all state through the pipeline — target, clone dir,
artifact dir, audit log, findings store, router, gate settings, and every
stage's output (recon, analyst, exploits, patches, reports, secrets, deps,
roadmap, score). After each stage, artifacts are written to disk as JSON and
an event is appended to the audit log. Gates are satisfied via stdin (CLI),
auto-approved (`--yes`), or a `gate_callback` the web UI uses to block a worker
thread until a browser click arrives.

### Docker Sandbox (`src/sandbox/`)

- `docker_runner.py` executes PoCs and verifier commands with `--network none`,
  `--read-only` rootfs, dropped capabilities, `no-new-privileges`, and CPU/
  memory/pids limits.
- `patch_verifier.py` copies the repo to a throwaway dir, drops in the
  regression test, runs it (expecting failure), applies the diff, and runs it
  again (expecting success) — only then is the patch marked verified.

If Docker is unavailable, the pipeline **continues**: PoCs are generated but
not executed, and hypotheses still proceed to Patch/Report rather than
dead-ending on missing tooling.

### Scanners & Analysis (`src/scanners/`, `src/roadmap.py`, `src/scoring.py`)

Deterministic, non-LLM scanners run alongside Recon and never block the
pipeline on failure:
- `scanners/secrets.py` — regex-based secret detection (AWS/GitHub/Slack/Stripe
  keys, private key blocks, JWTs, generic/`.env`-style assignments), with
  values redacted in output.
- `scanners/deps.py` — tries `osv-scanner`, `pip-audit`, `npm audit` (whichever
  is installed) against the repo's manifests.

`roadmap.py` merges code hypotheses + secrets + dependency findings into one
priority-ordered fix list with effort estimates. `scoring.py` derives a
per-category (secrets/dependencies/code/exploitability) 0–100 score and an
overall A–F grade, written after every stage so the web UI always has
something current to show.

### Storage Layer (`src/store/`)

- **`AuditLog`** — append-only JSONL at `data/audit.jsonl`; each entry SHA-256
  hashes the previous entry. `python -m src.main audit verify` checks the chain.
- **`FindingsStore`** — SQLite index at `data/findings.db`; also tracks
  `patch_validated` and a `dedupe_key` so `triage` can surface duplicate
  findings across runs.
- **`UsageStore`** — per-run and per-day LLM token/request totals, in the same
  SQLite file.

---

## Tech Stack

| Component | Library / Tool | Purpose |
|-----------|---------------|---------|
| LLM client | `google-genai >= 1.0.0` | Gemini API |
| LLM fallback | `anthropic`, `groq`, `openai` | Claude, Groq, and OpenRouter clients |
| JSON repair | `json-repair >= 0.30` | Fixes truncated/malformed LLM JSON output |
| Data validation | `pydantic >= 2.9` | Typed input/output models for every agent |
| Repo cloning | `gitpython >= 3.1` | Clone/checkout target repos at pinned refs |
| Code scanning | `semgrep >= 1.90` | Dataflow-aware static analysis during Recon |
| Syntax parsing | `tree-sitter`, `tree-sitter-languages` | AST-based code understanding |
| Web backend | `fastapi`, `uvicorn`, `python-multipart` | REST API + run orchestration for the UI |
| PDF export | `fpdf2`, `markdown` | Rendered report downloads |
| Frontend | React + Vite + TypeScript + Tailwind | `frontend/` — dashboard, run detail, chat |
| CLI / output | `rich >= 13.9` | Formatted terminal output, tables, progress |
| Sandbox | Docker (external) | Isolated PoC execution + patch verification |
| Database | SQLite (stdlib) | Findings, usage index |

---

## Project Structure

```
Bug-Bounty-/
├── .env                        # API keys (never commit)
├── requirements.txt
├── config/targets.json         # Authorization allowlist
├── src/
│   ├── main.py                 # CLI entry point
│   ├── orchestrator.py         # Pipeline runner + RunContext
│   ├── current_run.py          # Thread-local run id (for usage attribution)
│   ├── roadmap.py               # Prioritized fix roadmap
│   ├── scoring.py               # Per-category security score
│   ├── pdf_report.py            # PDF report rendering
│   ├── chat.py                  # "Ask Security AI" chat module
│   ├── agents/                  # Recon, Analyst, Exploit, Patch, Report
│   ├── scanners/                # secrets.py, deps.py
│   ├── models/router.py         # Multi-provider LLM router
│   ├── sandbox/                 # docker_runner.py, patch_verifier.py
│   ├── store/                   # audit.py, findings.py, usage.py, dashboard.py
│   └── web/                     # FastAPI app, threaded run manager, log tee
├── frontend/                    # React + Vite + Tailwind web UI
├── tests/                       # Offline pytest suite (MockProvider, no Docker/keys)
└── data/                        # Created at runtime (gitignored)
    ├── repos/                   # Cloned target repos
    ├── findings/<run_id>/       # Per-run JSON artifacts + reports
    ├── findings.db              # SQLite: findings + usage
    ├── cache/                   # Cached LLM responses
    └── audit.jsonl              # Tamper-evident event log
```

---

## Setup

```bash
make install          # creates .venv and installs requirements
cp .env.example .env  # add at least one provider key (Gemini free tier works)
```

Docker is optional but required to *validate* PoCs and *verify* patches;
without it the pipeline still generates every artifact and clearly reports
that validation was skipped. Get a free Gemini key at
https://aistudio.google.com/apikey.

---

## Running

```bash
python -m src.main list                                   # authorized targets
python -m src.main run pyyaml-old --yes                   # full pipeline, auto-approve gates
python -m src.main run pyyaml-old --top-n 3 --parallel    # exploit top 3, concurrently
python -m src.main stage juice-shop analyst                # stop after a stage
python -m src.main recon dvwa                               # recon only
python -m src.main run pyyaml-old --resume                 # reuse on-disk recon/analyst
python -m src.main diff pyyaml-old 3.11 3.12                # analyze only changed files
python -m src.main findings                                  # list findings from SQLite
python -m src.main triage                                    # duplicate findings across runs
python -m src.main dashboard -o report.html                  # standalone HTML dashboard
python -m src.main audit verify                               # check the audit hash chain
```

### Run options

| Flag | Effect |
|------|--------|
| `--yes` | Auto-approve the human gates (never auto-submits a report) |
| `--top-n N` | Exploit the top N ranked hypotheses instead of just #1 |
| `--parallel` | Run hypotheses concurrently (thread pool) |
| `--resume` | Reuse existing recon/analyst/scanner artifacts |
| `--no-cache` | Disable the on-disk LLM response cache |

---

## Web UI

`src/web/app.py` (FastAPI) exposes the same pipeline over HTTP: start/poll
runs, answer HITL gates from the browser, download PDF/Markdown reports, query
the dashboard/score/roadmap, and a chat endpoint for asking questions about a
run. `frontend/` (React + Vite + Tailwind) is the client. A submitted repo URL
can be **self-attested** through the UI, which appends it to
`config/targets.json` as an `attested` entry rather than requiring a manual
allowlist edit — the pipeline still refuses anything not in the allowlist.

```bash
# Backend
.venv/bin/uvicorn src.web.app:app --reload

# Frontend (separate terminal)
cd frontend && npm install && npm run dev
```

---

## Configuration

### `config/targets.json`

Only repositories listed here can be targeted — this is the authorization
allowlist. Entries added via the web UI's self-attestation flow are tagged
`"category": "attested"` with the attester's name and a timestamp.

### `.env`

See `.env.example` for the full list. At minimum, set one LLM provider key
(`GEMINI_API_KEY` recommended). Notable extras: `OLLAMA_MODEL` for a local
offline fallback, `SEMGREP_CONFIG` to point at an offline ruleset,
`PATCH_VERIFY_NETWORK=1` to let the verifier install test dependencies.

---

## Output Artifacts

Each run creates `data/findings/<target>_<timestamp>/`:

| File | Contents |
|------|----------|
| `01_recon.json` | Risky files, grep/Semgrep hits, file tree |
| `01b_secrets.json` | Secrets scanner hits |
| `01c_deps.json` | Dependency CVE scanner results |
| `02_analyst.json` | Ranked vulnerability hypotheses |
| `02b_roadmap.json` | Prioritized fix roadmap (code + secrets + deps) |
| `03_exploit_<id>.json` | PoC code, reproduction steps, sandbox result |
| `04_patch_<id>.json` | Unified diff, regression test, verification result |
| `05_report_<id>.json` / `.md` | Structured + Markdown disclosure report |
| `05_report_<id>_eli5.md` | Plain-English variant of the report |
| `06_score.json` | Per-category security score + grade |

---

## Safety Design

| Concern | Mitigation |
|---------|-----------|
| Targeting unauthorized repos | `config/targets.json` allowlist; unlisted repos are refused |
| Weaponized exploits | Exploit agent is system-prompted to write non-destructive, offline-only PoCs; `destructive=true` PoCs are refused before execution |
| Network exfiltration in PoC | Docker sandbox runs with `--network none` |
| Host filesystem damage | Sandbox mounts the workdir read-only; `--read-only` rootfs, dropped capabilities |
| Auto-submission of reports | Report stage writes to disk only; no calls to bug bounty platforms |
| Audit tampering | Each audit entry SHA-256-hashes the previous entry; `audit verify` checks the chain |
| Self-attested targets | Web UI attestations are recorded with attester identity + timestamp, not silently trusted |

---

## Limitations

- **Gemini free-tier quotas**: daily request limits per model; the router falls
  back through the model chain, then across providers, before giving up.
- **Python 2 PoCs**: some older vulnerabilities (e.g. PyYAML 3.12) assume
  Python 2 syntax that the Python 3.12 sandbox image may fail to execute.
- **No auto-patching**: a patch is a proposed, sandbox-verified diff — it is
  never applied to the target repo automatically.
- **Docker-less environments** (e.g. some sandboxed CI/Replit setups without
  user namespaces): PoC/patch validation is skipped; the pipeline still
  produces every artifact and says so explicitly.

---

## Environment Notes (Replit/Nix)

This project has also been run on Replit, which uses a Nix-based environment
with no standard `pip`/`python` in `PATH`.

- `libstdc++.so.6` (needed by `grpcio`, a `google-genai` dependency) may need
  `LD_LIBRARY_PATH` pointed at the Nix gcc lib store path.
- The Docker client may be present but the daemon requires user namespaces,
  which some sandboxes don't grant — see Limitations above.
- `google-generativeai` (old SDK) is deprecated; this project uses
  `google-genai >= 1.0.0`.

---

## Development

```bash
make test     # offline test suite — no network, no Docker, no API keys
make lint     # byte-compile all modules
```

The test suite uses a `MockProvider` and a monkeypatched sandbox, so the
entire pipeline (recon → analyst → exploit → patch → verify → report) is
exercised end-to-end without any external dependency.

## Disclaimer

For authorized security research and education only. You are responsible for
ensuring you have permission to test any target. The tool refuses anything not
on the allowlist and never submits reports on your behalf.
