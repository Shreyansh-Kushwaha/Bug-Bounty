# Bug Bounty AI Pipeline

An automated security research platform that uses chained AI agents to identify, validate, and generate patches for vulnerabilities in authorized open-source repositories. The system produces structured HackerOne-style reports ready for human review before any disclosure.

---

## Table of Contents

1. [What It Does](#what-it-does)
2. [Pipeline Stages](#pipeline-stages)
3. [Architecture](#architecture)
4. [Tech Stack](#tech-stack)
5. [Project Structure](#project-structure)
6. [Setup](#setup)
7. [Running](#running)
8. [Configuration](#configuration)
9. [Output Artifacts](#output-artifacts)
10. [Safety Design](#safety-design)
11. [Limitations](#limitations)
12. [Environment Notes (Replit/Nix)](#environment-notes-replitnih)

---

## What It Does

Given a target repository listed in the authorization allowlist, the pipeline:

1. **Scans** the repo for risky code patterns (unsafe deserialization, eval/exec, SQL sinks, etc.)
2. **Analyzes** findings using an LLM to form ranked vulnerability hypotheses with CWE classification
3. **Generates** a non-destructive proof-of-concept (PoC) script for the top hypothesis
4. **Executes** the PoC in an isolated Docker sandbox to validate it (if Docker is available)
5. **Proposes** a minimal patch with a regression test
6. **Drafts** a responsible-disclosure report (HackerOne format) with CVSS score

Human confirmation gates sit before the Exploit and Report stages. The report is written to disk but **never auto-submitted**.

---

## Pipeline Stages

```
Repo Clone
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  Stage 1: Recon                                     │
│  • Clones repo at pinned ref                        │
│  • Runs grep/semgrep patterns for risky sinks       │
│  • Outputs: list of risky files + snippets          │
└───────────────────────┬─────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│  Stage 2: Analyst                                   │
│  • LLM reads risky files and source context         │
│  • Forms ranked vulnerability hypotheses            │
│  • Each hypothesis has: CWE, severity, file, line,  │
│    description, evidence snippet                    │
└───────────────────────┬─────────────────────────────┘
                        │
               [HUMAN GATE: proceed?]
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│  Stage 3: Exploit                                   │
│  • LLM writes a non-destructive PoC script          │
│  • PoC is executed in a Docker sandbox (if avail.)  │
│  • Validates by checking stdout for sentinel string │
│  • Outputs: validated=true/false + stdout/stderr    │
└───────────────────────┬─────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│  Stage 4: Patch                                     │
│  • LLM proposes the minimal secure fix              │
│  • Outputs unified diff + regression test file      │
└───────────────────────┬─────────────────────────────┘
                        │
               [HUMAN GATE: generate report?]
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│  Stage 5: Report                                    │
│  • LLM drafts HackerOne-style vulnerability report  │
│  • Includes: title, CVSS vector/score, summary,     │
│    steps to reproduce, PoC, impact, remediation,    │
│    references                                       │
│  • Saved as Markdown — never auto-submitted         │
└─────────────────────────────────────────────────────┘
```

---

## Architecture

### Agent Pattern

Every pipeline stage is a typed agent inheriting from `Agent[TInput, TOutput]` in `src/agents/base.py`.

```python
class Agent(ABC, Generic[TInput, TOutput]):
    def system_prompt(self) -> str: ...      # LLM instruction
    def build_prompt(self, inp) -> str: ...  # formats input → prompt
    def output_model(self) -> type[TOutput]: # Pydantic model for JSON validation
    def run(self, inp) -> TOutput: ...       # calls router → parses JSON → validates
```

Each agent:
- Calls the `ModelRouter` with its assigned tier
- Receives a text response from the LLM
- Extracts JSON from `` ```json ``` `` fences or raw text
- Uses `json-repair` as a fallback for slightly malformed JSON
- Validates the parsed dict against a Pydantic model

### LLM Router (`src/models/router.py`)

`ModelRouter` supports three providers (Gemini, Groq, OpenRouter) with three quality tiers:

| Tier | Used By | Primary Model |
|------|---------|---------------|
| `FAST` | Recon, Report | `gemini-3-flash-preview` |
| `REASONING` | Analyst | `gemini-3-flash-preview` |
| `CODER` | Exploit, Patch | `gemini-3-flash-preview` |

Failover behavior:
- Within `GeminiProvider`: tries `gemini-3-flash-preview` → `gemini-2.5-flash` → `gemini-2.5-flash-lite` on 503/429
- Across providers: Gemini → Groq → OpenRouter (if keys are configured)
- Exponential backoff (5s, 10s, 20s) on rate-limit and overload errors

### Orchestrator (`src/orchestrator.py`)

`RunContext` is a dataclass that carries all state through the pipeline:

```python
@dataclass
class RunContext:
    run_id: str          # timestamp-based slug, e.g. "pyyaml-old_1776783330"
    target: dict         # entry from config/targets.json
    clone_dir: Path      # where the repo is cloned
    artifact_dir: Path   # data/findings/<run_id>/
    audit: AuditLog
    store: FindingsStore
    auto_approve: bool   # --yes flag
```

After each stage, artifacts are written to disk as JSON and an event is appended to the audit log.

### Docker Sandbox (`src/sandbox/docker_runner.py`)

PoC execution uses Docker with strict safety settings:

```
docker run --rm
  --network none          # no internet access
  --read-only             # immutable container filesystem
  --tmpfs /tmp:size=64m   # small writable scratch space
  --memory 256m           # RAM cap
  --cpus 0.5              # CPU cap
  --pids-limit 128        # no fork bombs
  --cap-drop ALL          # drop all Linux capabilities
  --security-opt no-new-privileges
  -v <workdir>:/work:ro   # PoC files mounted read-only
```

Supported runtimes: Python 3.12, Node.js 20, Alpine bash.

If Docker is not available, the pipeline **continues** — it notes the PoC as unexecuted and proceeds to Patch and Report stages anyway.

### Storage Layer (`src/store/`)

**`AuditLog` (`audit.py`)**
- Append-only JSONL file at `data/audit.jsonl`
- Each entry contains: `timestamp`, `event_type`, `payload`, `sha256` (hash of previous entry)
- Hash chain allows tamper detection: `python -m src.main audit verify`

**`FindingsStore` (`findings.py`)**
- SQLite database at `data/findings.db`
- Schema: `run_id`, `target`, `hypothesis_id`, `cwe`, `severity`, `file`, `line_range`, `title`, `validated`, `has_patch`, `has_report`, `artifact_dir`, `metadata`
- Query: `python -m src.main findings [--target <name>]`

---

## Tech Stack

| Component | Library / Tool | Purpose |
|-----------|---------------|---------|
| LLM client | `google-genai >= 1.0.0` | Gemini API (new SDK, replaces deprecated `google-generativeai`) |
| LLM fallback | `groq`, `openai` | Groq and OpenRouter provider clients |
| Data validation | `pydantic >= 2.9` | Typed input/output models for every agent |
| JSON repair | `json-repair >= 0.30` | Fixes truncated/malformed LLM JSON output |
| Repo cloning | `gitpython >= 3.1` | Clone and checkout target repos at pinned refs |
| Code scanning | `semgrep >= 1.90` | Pattern-based static analysis during Recon |
| Syntax parsing | `tree-sitter`, `tree-sitter-languages` | AST-based code understanding |
| CLI / output | `rich >= 13.9` | Formatted terminal output, tables, progress |
| Environment | `python-dotenv >= 1.0` | Loads `.env` API keys |
| Sandbox | Docker (external) | Isolated PoC execution |
| Database | SQLite (stdlib) | Findings index |

---

## Project Structure

```
Bug-Bounty-/
├── .env                        # API keys (never commit)
├── requirements.txt            # Python dependencies
├── config/
│   └── targets.json            # Authorization allowlist
├── src/
│   ├── main.py                 # CLI entry point (argparse)
│   ├── orchestrator.py         # Pipeline runner + RunContext
│   ├── agents/
│   │   ├── base.py             # Agent[TInput,TOutput] base class + JSON parser
│   │   ├── recon.py            # Stage 1: file scanning
│   │   ├── analyst.py          # Stage 2: hypothesis generation
│   │   ├── exploit.py          # Stage 3: PoC writing + sandbox execution
│   │   ├── patch.py            # Stage 4: fix + regression test
│   │   └── report.py           # Stage 5: disclosure report
│   ├── models/
│   │   └── router.py           # Multi-provider LLM router with fallover
│   ├── sandbox/
│   │   └── docker_runner.py    # Docker sandbox wrapper
│   └── store/
│       ├── audit.py            # SHA256 hash-chained audit log
│       └── findings.py         # SQLite findings index
├── data/                       # Created at runtime
│   ├── repos/                  # Cloned target repos
│   ├── findings/               # Per-run JSON artifacts + reports
│   │   └── <run_id>/
│   │       ├── 01_recon.json
│   │       ├── 02_analyst.json
│   │       ├── 03_exploit_H1.json
│   │       ├── 04_patch_H1.json
│   │       ├── 05_report_H1.json
│   │       └── 05_report_H1.md   ← human-readable report
│   ├── findings.db             # SQLite index
│   └── audit.jsonl             # Tamper-evident event log
└── venv/                       # Python virtual environment
```

---

## Setup

### Requirements

- Python 3.12 (provided via Nix in Replit)
- At least one LLM API key: Gemini is recommended and free
- Docker (optional — needed for PoC sandbox execution)

### Steps

```bash
# 1. Create virtual environment
python3.12 -m venv venv

# 2. Install dependencies
venv/bin/pip install -r requirements.txt

# 3. Configure API keys
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY
```

Get a free Gemini API key at: https://aistudio.google.com/apikey

---

## Running

### In a standard Python environment

```bash
# List authorized targets
python -m src.main list

# Run full pipeline (with human confirmation prompts)
python -m src.main run pyyaml-old

# Run fully automated (skip prompts)
python -m src.main run pyyaml-old --yes

# Run only the Recon stage
python -m src.main recon pyyaml-old

# Run up to a specific stage
python -m src.main stage pyyaml-old analyst

# Query findings database
python -m src.main findings
python -m src.main findings --target pyyaml-old

# Verify audit log integrity
python -m src.main audit verify
```

### In the Replit/Nix environment

The `LD_LIBRARY_PATH` must be set for `grpcio` (used by `google-genai`):

```bash
export LD_LIBRARY_PATH=/mnt/nixmodules/nix/store/6vzcxjxa2wlh3p9f5nhbk62bl3q313ri-gcc-14.3.0-lib/lib

venv/bin/python -m src.main run pyyaml-old --yes
```

---

## Configuration

### `config/targets.json`

Only repositories listed here can be targeted. This is the authorization allowlist.

```json
[
  {
    "name": "pyyaml-old",
    "repo": "https://github.com/yaml/pyyaml",
    "ref": "3.12",
    "category": "benchmark",
    "cve": "CVE-2017-18342"
  },
  {
    "name": "juice-shop",
    "repo": "https://github.com/juice-shop/juice-shop",
    "ref": "master",
    "category": "training"
  },
  {
    "name": "dvwa",
    "repo": "https://github.com/digininja/DVWA",
    "ref": "master",
    "category": "training"
  }
]
```

To add a new target, append an entry here before running.

### `.env`

```
GEMINI_API_KEY=your_key_here        # Required (recommended)
GROQ_API_KEY=                       # Optional fallback
OPENROUTER_API_KEY=                 # Optional fallback
GITHUB_TOKEN=                       # Optional: higher git clone rate limits
```

---

## Output Artifacts

Each run creates a directory at `data/findings/<target>_<timestamp>/`:

| File | Contents |
|------|----------|
| `01_recon.json` | List of risky files, grep/semgrep hits, file tree |
| `02_analyst.json` | Ranked vulnerability hypotheses with CWE, severity, evidence |
| `03_exploit_H1.json` | PoC code, reproduction steps, sandbox validation result |
| `04_patch_H1.json` | Unified diff, regression test code, rationale |
| `05_report_H1.json` | Structured report data (JSON) |
| `05_report_H1.md` | Human-readable HackerOne-style Markdown report |

### Example Report (pyyaml-old CVE-2017-18342)

```
# Remote Code Execution via Default Unsafe Deserialization in yaml.load

Severity: Critical (CVSS 9.8)
CWE: CWE-502
CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

Summary: PyYAML 3.12 uses yaml.load() without a Loader argument, defaulting
to UnsafeLoader which allows arbitrary Python object instantiation and RCE
via !!python/object/apply tags in attacker-controlled YAML input.

Remediation: Change default Loader from Loader to SafeLoader across all
yaml.load(), yaml.load_all(), yaml.scan(), yaml.parse() functions.
```

---

## Safety Design

| Concern | Mitigation |
|---------|-----------|
| Targeting unauthorized repos | `config/targets.json` allowlist; pipeline refuses unlisted repos |
| Weaponized exploits | Exploit agent is system-prompted to write non-destructive, offline-only PoCs; `destructive=true` PoCs are refused |
| Network exfiltration in PoC | Docker sandbox runs with `--network none` |
| Host filesystem damage | Docker sandbox mounts workdir read-only; `--read-only` rootfs |
| Auto-submission of reports | Report stage writes to disk only; no HTTP calls to bug bounty platforms |
| Audit tampering | Each audit log entry SHA256-hashes the previous entry; `audit verify` checks the chain |

---

## Limitations

- **No Docker in Replit**: The sandbox cannot execute PoCs in this environment (user namespaces are blocked). PoCs are generated and saved but not executed. The pipeline continues to Patch and Report anyway.
- **Gemini free-tier quotas**: Daily request limits per model. If quota is exhausted, the router falls back through the model chain; if all are exhausted, wait for UTC midnight reset.
- **Single hypothesis per run**: The pipeline currently exploits only the top-ranked hypothesis (rank=1). Multiple hypotheses require multiple runs.
- **Python 2 PoCs**: Some older vulnerabilities (like PyYAML 3.12) require Python 2 syntax; the sandbox uses Python 3.12 which may fail to execute them.
- **No auto-patching**: The patch is a proposed diff — it is never applied to the repo automatically.

---

## Environment Notes (Replit/Nix)

This project was developed and tested on Replit, which uses a Nix-based environment with no standard `pip`/`python` in PATH.

**Key environment facts:**
- Python 3.12 lives at: `/mnt/nixmodules/nix/store/949pqmg8w3gv7ycqs7g5iymmzpp1jza6-python3-3.12.12-env/bin/python3.12`
- `libstdc++.so.6` (needed by `grpcio`) lives at: `/mnt/nixmodules/nix/store/6vzcxjxa2wlh3p9f5nhbk62bl3q313ri-gcc-14.3.0-lib/lib`
- Docker client is installed but the daemon requires root/user-namespaces, neither available in Replit
- `google-generativeai` (old SDK) is deprecated — this project uses `google-genai >= 1.0.0`
- `gemini-2.5-pro` and `gemini-2.0-flash*` models have `limit: 0` on the free tier for the configured key — use `gemini-3-flash-preview` or `gemini-2.5-flash`
