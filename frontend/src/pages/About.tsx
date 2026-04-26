import { Link } from "react-router-dom";
import { CtaPanel, PageHeader } from "../components/ui";

const safety: [string, React.ReactNode][] = [
  ["Targeting unauthorized repos", <>Allowlist enforcement at submit time + attestation in audit log.</>],
  ["Weaponized exploits", <>Exploit agent is system-prompted for non-destructive PoCs; <code>destructive=true</code> is refused.</>],
  ["Network exfiltration in PoC", <>Sandbox runs with <code>--network none</code>.</>],
  ["Host filesystem damage", <>Read-only rootfs; workdir mounted <code>:ro</code>; capped <code>--memory</code>, <code>--cpus</code>, <code>--pids-limit</code>.</>],
  ["Auto-submission of reports", <>Report stage writes to disk only — no HTTP calls to disclosure platforms.</>],
  ["Audit tampering", <>Each entry SHA256-hashes the previous entry. <code>audit verify</code> checks the chain.</>],
];

const stack: [string, React.ReactNode][] = [
  ["LLM SDK", <><code>google-genai</code> (replaces deprecated <code>google-generativeai</code>)</>],
  ["Fallback providers", <><code>groq</code>, OpenRouter (<code>openai</code> client)</>],
  ["Validation", <>Pydantic v2 models for every agent's I/O</>],
  ["JSON repair", <><code>json-repair</code> for slightly malformed model output</>],
  ["Static analysis", <><code>semgrep</code>, AST via <code>tree-sitter</code></>],
  ["Sandbox", <>Docker (graceful skip when unavailable)</>],
  ["Web UI", <>FastAPI JSON API + React + Vite + Tailwind v3</>],
  ["Storage", <>SQLite findings index + append-only JSONL audit</>],
];

export default function About() {
  return (
    <>
      <PageHeader
        eyebrow="About"
        title="Security research that respects boundaries"
        body={
          <>
            Bug-Bounty Pipeline is an experimental platform that chains AI agents to identify, validate, and patch
            vulnerabilities in <strong>authorized</strong> open-source repositories. Every action is logged. No exploit is
            weaponized. No report is auto-disclosed.
          </>
        }
      />

      <section className="card mb-5">
        <h2 className="text-lg font-semibold mb-3 text-fg">What this project is</h2>
        <p className="text-fg-muted">
          A reproducible research harness around five LLM-driven stages — Recon, Analyst, Exploit, Patch, Report — with
          provider failover, structured artifacts, and a SHA256 hash-chained audit log.
        </p>
        <p className="text-fg-muted">
          It's intentionally narrow in scope: we run only against repositories listed in <code>config/targets.json</code>.
          Adding a target requires an attestation that the user owns or has written permission to test the repo, and
          that attestation is recorded.
        </p>
      </section>

      <section className="card mb-5">
        <h2 className="text-lg font-semibold mb-3 text-fg">Safety design</h2>
        <KvTable rows={safety} headers={["Concern", "Mitigation"]} />
      </section>

      <section className="card mb-5">
        <h2 className="text-lg font-semibold mb-3 text-fg">Tech stack</h2>
        <KvTable rows={stack} headers={["Layer", "Tool"]} />
      </section>

      <section className="card mb-5">
        <h2 className="text-lg font-semibold mb-3 text-fg">Limitations</h2>
        <ul className="pl-5 text-fg-muted">
          <li>No Docker in Replit — PoCs are generated and saved but cannot be executed there.</li>
          <li>Gemini free-tier quotas reset daily at UTC midnight.</li>
          <li>Each run currently exploits only the top-ranked hypothesis.</li>
          <li>Patches are <em>proposed</em> diffs — they are never applied to the repo automatically.</li>
        </ul>
      </section>

      <CtaPanel
        title="Ready to run something?"
        body="Open the dashboard, attest the target, and start a recon stage."
      >
        <Link to="/dashboard" className="btn">Open the dashboard</Link>
        <Link to="/features" className="btn btn-secondary">See the pipeline stages</Link>
      </CtaPanel>
    </>
  );
}

function KvTable({ headers, rows }: { headers: [string, string]; rows: [string, React.ReactNode][] }) {
  return (
    <div className="overflow-x-auto">
      <table className="data-table">
        <thead>
          <tr>{headers.map((h) => <th key={h}>{h}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map(([k, v], i) => (
            <tr key={i}>
              <td className="text-fg">{k}</td>
              <td className="text-fg-muted">{v}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
