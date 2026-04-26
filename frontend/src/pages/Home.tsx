import { Link } from "react-router-dom";
import {
  ArrowRight, ArrowUpRight, Brain, CheckSquare, Code2, Cpu,
  FileText, Search, Shield, Sparkles, Terminal,
} from "lucide-react";
import AnimatedBg from "../components/AnimatedBg";

/**
 * Bento-grid landing page.
 * Layout (12-col on desktop, 6-col on mobile):
 *
 *   ┌──────────── HERO (col-8) ────────────┬───── STATS (col-4) ─────┐
 *   │  Big headline w/ calligraphy accent   │  3 stacked stat tiles  │
 *   ├──── TERMINAL DEMO (col-7, row-2) ────┼─── PIPELINE TILE (col-5)┤
 *   │  Animated CLI preview                 │  Vertical timeline     │
 *   ├───────────────────────────────────────┤   ┌────────────────────┤
 *   │                                       │   │  CTA TILE (col-5)  │
 *   ├───── MANIFESTO STRIP (col-12) ────────┴───┴────────────────────┤
 *   ├ FEATURE (4) │ FEATURE (4) │ FEATURE (4) ──────────────────────┤
 *   └────────────────────────────────────────────────────────────────┘
 */
export default function Home() {
  return (
    <div className="space-y-6">
      {/* ===== HERO STRIP with animated background — full viewport bleed ===== */}
      <section className="relative w-screen ml-[calc(50%-50vw)] -mt-8 px-6 pt-14 pb-10 overflow-hidden">
        <AnimatedBg />

        <div className="relative max-w-site mx-auto bento">
          {/* Big hero tile */}
          <div className="col-8 row-2 flex flex-col justify-between">
            <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-fg-dim mb-4">
              <span className="inline-block w-2 h-2 rounded-full bg-ok" />
              Live · authorized targets only
            </div>

            <h1 className="text-[2.4rem] sm:text-5xl md:text-[3.6rem] font-semibold tracking-tight leading-[1.04] text-fg">
              Five agents
              <br />
              <span className="script text-grad text-[3.4rem] sm:text-[4.6rem] md:text-[5.6rem]">hunt &amp; patch</span>{" "}
              <span className="text-fg-muted font-normal">vulnerabilities</span>
              <br />
              while you watch.
            </h1>

            <p className="mt-5 max-w-xl text-fg-muted">
              Recon, hypothesis, exploit, patch, and disclosure — chained, sandboxed, and audit-logged. You
              hold the keys at every gate.
            </p>

            <div className="mt-6 flex gap-3 flex-wrap">
              <Link to="/dashboard" className="btn">
                Run a pipeline <ArrowRight size={16} strokeWidth={2.5} />
              </Link>
              <Link to="/features" className="btn btn-secondary">
                <Sparkles size={14} /> What's inside
              </Link>
            </div>
          </div>

          {/* Stat tiles (right rail) */}
          <StatTile className="col-4" big="5" small="typed agents" hint="recon → report" />
          <StatTile className="col-4" big="3" small="model tiers" hint="fast · reasoning · coder" />
          <StatTile className="col-4" big="∞" small="audit chain" hint="SHA-256 hash-linked" />
        </div>
      </section>

      {/* ===== Bento row 2 — terminal demo + pipeline + CTA ===== */}
      <section className="bento">
        <div className="col-7 row-3 flex flex-col">
          <Eye>The pipeline, on the wire</Eye>
          <p className="text-fg-muted text-sm mb-3">
            Spin it up in one command — or use the dashboard. Either way, every event lands in <code>data/audit.jsonl</code>.
          </p>
          <div className="term flex-1">
            <div className="term-bar"><span/><span/><span/></div>
            <div><span className="prompt">$</span> python -m src.main run <span className="arg">pyyaml-old</span> --yes</div>
            <div className="text-fg-dim">────────── recon ──────────</div>
            <div>scanning 1,284 files… <span className="ok">4 risky sinks</span></div>
            <div className="text-fg-dim">────────── analyst ──────────</div>
            <div>3 hypotheses · top: <span className="ok">CWE-502 Critical</span></div>
            <div className="text-fg-dim">────────── exploit ──────────</div>
            <div>PoC validated <span className="ok">✓</span></div>
            <div className="text-fg-dim">────────── patch ──────────</div>
            <div>diff: 1 file, 3 lines · regression test <span className="ok">✓</span></div>
            <div className="text-fg-dim">────────── report ──────────</div>
            <div>05_report_H1.md written <span className="caret" /></div>
          </div>
        </div>

        <div className="col-5">
          <Eye>How it flows</Eye>
          <ol className="timeline list-none m-0 p-0 pl-6">
            <li><strong>Recon</strong> grep + Semgrep on the cloned repo</li>
            <li><strong>Analyst</strong> ranks hypotheses with CWE + evidence</li>
            <li><strong>Exploit</strong> non-destructive PoC, sandboxed</li>
            <li><strong>Patch</strong> minimal diff + regression test</li>
            <li><strong>Report</strong> HackerOne-style markdown</li>
          </ol>
        </div>

        <div
          className="col-5"
          style={{ background: "linear-gradient(135deg, var(--accent-soft), transparent)" }}
        >
          <Eye>Built for review, not auto-fire</Eye>
          <p className="text-fg-muted text-sm">
            Two human gates sit before exploit and report. Hit <em>approve</em> to proceed, <em>abort</em> to roll
            back. Decisions are logged, signed, and immutable.
          </p>
          <Link to="/about" className="inline-flex items-center gap-1.5 text-accent text-sm mt-3">
            Read the safety design <ArrowUpRight size={14} />
          </Link>
        </div>
      </section>

      {/* ===== Manifesto strip — calligraphy ===== */}
      <section className="bento">
        <div
          className="col-12 text-center py-12 px-6"
          style={{
            background: "radial-gradient(ellipse at center, var(--accent-soft) 0%, transparent 70%)",
          }}
        >
          <div className="text-fg-dim uppercase tracking-[0.2em] text-xs mb-3">a quiet promise</div>
          <p className="text-2xl sm:text-3xl md:text-4xl font-semibold tracking-tight text-fg leading-snug max-w-3xl mx-auto">
            We don't <span className="script text-grad text-4xl sm:text-5xl md:text-6xl">weaponize</span>.
            We don't auto-disclose.
            <br className="hidden sm:block" />
            We <span className="script text-grad text-4xl sm:text-5xl md:text-6xl">document</span> — every byte, every gate, every decision.
          </p>
        </div>
      </section>

      {/* ===== Feature tiles ===== */}
      <section className="bento">
        <Feature className="col-4" icon={Search}      title="Pattern-driven recon"      body="Semgrep + grep over a clean clone — unsafe sinks surface before the LLM ever sees the file." />
        <Feature className="col-4" icon={Brain}       title="Three model tiers"          body="Fast · reasoning · coder. Provider failover Gemini → Groq → OpenRouter when quotas bite." />
        <Feature className="col-4" icon={Shield}      title="Sandboxed PoCs"             body="Docker --network none, read-only roots, capped CPU/RAM/PIDs. Skip cleanly when no Docker." />
        <Feature className="col-4" icon={CheckSquare} title="Human gates"                body="Approve or abort before exploit and before report. Choices live in the audit chain." />
        <Feature className="col-4" icon={Code2}       title="Patch + regression"         body="A unified diff that builds, plus a test that fails before the fix and passes after." />
        <Feature className="col-4" icon={FileText}    title="HackerOne-shaped reports"   body="Title, CVSS vector, summary, repro, impact, remediation. Markdown to disk — never wired up." />
      </section>

      {/* ===== Bottom CTA — split tile ===== */}
      <section className="bento">
        <div className="col-8 flex flex-col justify-center">
          <Eye>When you're ready</Eye>
          <h2 className="text-2xl sm:text-3xl font-semibold text-fg leading-tight">
            Pick a target. <span className="script text-grad text-4xl sm:text-5xl">Sign your name.</span> Watch it run.
          </h2>
          <p className="text-fg-muted mt-2">
            The dashboard is the only door — it's the only place that captures attestation.
          </p>
        </div>
        <div className="col-4 flex flex-col justify-center gap-2">
          <Link to="/dashboard" className="btn">
            <Terminal size={15} /> Open dashboard
          </Link>
          <Link to="/features" className="btn btn-secondary">
            <Cpu size={15} /> See features
          </Link>
        </div>
      </section>
    </div>
  );
}

function StatTile({ className = "", big, small, hint }: { className?: string; big: string; small: string; hint: string }) {
  return (
    <div className={`${className} flex flex-col justify-center`}>
      <div className="text-5xl font-semibold leading-none text-fg tabular-nums">{big}</div>
      <div className="mt-1 text-fg uppercase tracking-wider text-xs">{small}</div>
      <div className="text-fg-dim text-xs mt-0.5">{hint}</div>
    </div>
  );
}

function Feature({
  className = "", icon: Icon, title, body,
}: { className?: string; icon: typeof Search; title: string; body: string }) {
  return (
    <div className={className}>
      <div className="w-10 h-10 rounded-lg grid place-items-center mb-3 bg-accent-soft text-accent">
        <Icon size={20} />
      </div>
      <h3 className="font-semibold text-fg mb-1">{title}</h3>
      <p className="text-sm text-fg-muted m-0">{body}</p>
    </div>
  );
}

function Eye({ children }: { children: React.ReactNode }) {
  return (
    <div className="text-[11px] uppercase tracking-[0.18em] text-fg-dim mb-2 font-semibold">{children}</div>
  );
}
