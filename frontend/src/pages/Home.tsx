import { Link } from "react-router-dom";
import {
  ArrowRight, Brain, CheckSquare, Code2, FileText, Search, Shield,
} from "lucide-react";
import { CtaPanel } from "../components/ui";

const features = [
  { icon: Search,      title: "Pattern-driven recon",  body: "Semgrep + grep sweeps over the cloned repo to surface unsafe sinks: deserialization, eval/exec, SQL concatenation, and more." },
  { icon: Brain,       title: "Reasoning agents",      body: "Three model tiers — fast, reasoning, coder — with provider failover across Gemini, Groq, and OpenRouter." },
  { icon: Shield,      title: "Sandboxed PoCs",        body: "Generated proofs run in ephemeral Docker containers with --network none, read-only roots, capped CPU/RAM/PIDs." },
  { icon: CheckSquare, title: "Human-in-the-loop",     body: "Approval gates sit before Exploit and Report. Nothing weaponized, nothing disclosed without you in the loop." },
  { icon: Code2,       title: "Patch + regression",    body: "Each finding ships with a unified diff and a regression test designed to fail before the fix and pass after." },
  { icon: FileText,    title: "HackerOne-ready reports", body: "Structured Markdown reports with CVSS vector, reproduction steps, impact, and remediation — never auto-submitted." },
];

const stages = [
  { n: 1, title: "Recon",   body: "Clone the repo at a pinned ref, run pattern scans, and emit a ranked list of risky files and snippets." },
  { n: 2, title: "Analyst", body: "An LLM forms vulnerability hypotheses with CWE, severity, evidence, and a precise file/line reference." },
  { n: 3, title: "Exploit", body: "A non-destructive PoC is generated and validated in a Docker sandbox. Human gate before this stage." },
  { n: 4, title: "Patch",   body: "The Coder tier proposes a minimal diff and a regression test that distinguishes vulnerable vs. patched behavior." },
  { n: 5, title: "Report",  body: "A HackerOne-style Markdown report is written to disk with CVSS, summary, repro, impact, and remediation." },
];

export default function Home() {
  return (
    <>
      <section className="hero-grad relative -mt-8 -mx-6 px-6 py-20 text-center border-b border-border">
        <div className="max-w-[820px] mx-auto relative">
          <div className="flex gap-2 justify-center flex-wrap mb-4">
            <span className="badge"><span className="w-1.5 h-1.5 rounded-full bg-ok" /> Authorized targets only</span>
            <span className="badge">5-stage AI pipeline</span>
          </div>
          <h1 className="text-4xl md:text-6xl font-semibold leading-tight tracking-tight mb-4 text-fg">
            Find, validate, and patch vulnerabilities <span className="text-grad">with AI agents</span>
          </h1>
          <p className="text-base md:text-lg max-w-xl mx-auto mb-7 text-fg-muted">
            Chain LLM-driven agents for recon, hypothesis, exploit, patch, and disclosure — with human gates and a tamper-evident audit log at every step.
          </p>
          <div className="flex gap-3 justify-center flex-wrap">
            <Link to="/dashboard" className="btn">
              Start a run <ArrowRight size={16} strokeWidth={2.5} />
            </Link>
            <Link to="/features" className="btn btn-secondary">See how it works</Link>
          </div>
        </div>
      </section>

      <section className="mt-12">
        <div className="max-w-[640px] mx-auto text-center mb-8">
          <span className="eyebrow">Why this pipeline</span>
          <h2 className="text-2xl md:text-3xl font-semibold tracking-tight text-fg">
            Security research, but with guardrails
          </h2>
          <p className="mt-2 text-fg-muted">
            Built for authorized OSS repositories. Every stage is sandboxed, every action is logged, and reports are never auto-submitted.
          </p>
        </div>

        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {features.map((f) => (
            <article key={f.title}
              className="card transition-all duration-200 hover:-translate-y-0.5 hover:shadow-pop">
              <div className="w-10 h-10 rounded-lg grid place-items-center mb-3 bg-accent-soft text-accent">
                <f.icon size={22} />
              </div>
              <h3 className="font-semibold mb-1 text-fg">{f.title}</h3>
              <p className="text-sm m-0 text-fg-muted">{f.body}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="mt-14">
        <div className="text-center mb-6">
          <span className="eyebrow">Pipeline at a glance</span>
          <h2 className="text-xl md:text-2xl font-semibold text-fg">Five stages, five typed agents</h2>
        </div>
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
      </section>

      <CtaPanel
        eyebrow="Ready when you are"
        title="Run the pipeline against an authorized target"
        body="Add an attestation, pick a stop point, and watch live progress in the dashboard."
      >
        <Link to="/dashboard" className="btn">Open the dashboard</Link>
        <Link to="/about" className="btn btn-secondary">Read the safety design</Link>
      </CtaPanel>
    </>
  );
}
