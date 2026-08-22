import { Link } from "react-router-dom";
import { Activity, AlertCircle, FileText, FolderArchive, Layers, RefreshCw } from "lucide-react";
import { CtaPanel, PageHeader } from "../components/ui";

const stages = [
  { n: 1, title: "Recon — pattern sweep on a clean clone",
    body: "Clones the target at a pinned ref, then runs grep + Semgrep patterns for unsafe deserialization, eval/exec, SQL string concatenation, command injection, weak crypto, and more. Outputs a ranked list of risky files and snippets." },
  { n: 2, title: "Analyst — hypothesis generation",
    body: "An LLM reads risky files in context and emits ranked vulnerability hypotheses. Each one carries a CWE, severity, file/line, evidence snippet, and a one-paragraph mechanism description — validated against a Pydantic model." },
  { n: 3, title: "Exploit — non-destructive PoC + sandbox",
    body: "The Coder tier writes a PoC script for the top hypothesis. We execute it inside Docker with --network none, a read-only root, and capped memory/CPU/PIDs. Validation is by sentinel string in stdout — never by side effect." },
  { n: 4, title: "Patch — minimal diff + regression test",
    body: "Proposes a unified diff against the cloned repo and a regression test that fails before the fix and passes after. The patch is never applied to the live repo — it lives as an artifact." },
  { n: 5, title: "Report — HackerOne-style Markdown",
    body: "Drafts a structured report with title, CVSS vector + score, summary, repro steps, impact, remediation, and references. Saved to disk as Markdown — never auto-submitted to a disclosure platform." },
];

const platform = [
  { icon: Activity,     title: "Live progress",          body: "React polls /api/runs/{id} every two seconds — stage chips, log tail, gate prompts, and artifacts appear as they're produced." },
  { icon: Layers,       title: "Token + quota tracking", body: "Per-model daily request and token counts, with a UTC reset bar — so you never get blindsided by a hit quota mid-run." },
  { icon: AlertCircle,  title: "Audit log viewer",       body: "Every event (run start, stage transition, gate decision, error) is appended to a SHA256 hash-chained log. The viewer flags broken chains." },
  { icon: FolderArchive,title: "Per-run artifacts",      body: "JSON for each stage plus a Markdown report — all rendered with stage-specific viewers (hypotheses, diffs, PoCs, etc.)." },
  { icon: RefreshCw,    title: "Provider failover",      body: "Gemini → Groq → OpenRouter chain with exponential backoff on 429/503. Per-model fallback handles individual quota exhaustion." },
  { icon: FileText,     title: "Findings index",         body: "SQLite-backed cross-run index. Filter by target; see severity, CWE, validation, patch, and report status at a glance." },
];

export default function Features() {
  return (
    <>
      <PageHeader
        align="center"
        eyebrow="Features"
        title="Five typed agents, three model tiers, one audited pipeline"
        body="Each stage is a typed Agent[TInput, TOutput] — its input and output are Pydantic models, so we can swap models, providers, and prompts without touching the orchestrator."
      />

      <h2 className="text-xl text-center font-semibold mb-6 text-fg">Pipeline stages</h2>
      <div className="grid gap-2">
        {stages.map((s) => (
          <div key={s.n} className="stage-row">
            <div className="num">{s.n}</div>
            <div>
              <h3 className="font-semibold mb-1 text-fg">{s.title}</h3>
              <p className="text-sm m-0 text-fg-muted">{s.body}</p>
            </div>
          </div>
        ))}
      </div>

      <h2 className="text-xl text-center font-semibold mt-12 mb-6 text-fg">Platform features</h2>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {platform.map((f) => (
          <article key={f.title} className="card">
            <div className="w-10 h-10 rounded-lg grid place-items-center mb-3 bg-accent-soft text-accent">
              <f.icon size={22} />
            </div>
            <h3 className="font-semibold mb-1 text-fg">{f.title}</h3>
            <p className="text-sm m-0 text-fg-muted">{f.body}</p>
          </article>
        ))}
      </div>

      <CtaPanel
        title="Try it on a repo you control"
        body="Add an attestation, choose Recon only for a low-cost first run, and watch the stages light up."
      >
        <Link to="/dashboard" className="btn">Open the dashboard</Link>
      </CtaPanel>
    </>
  );
}
