import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Check, Pause, X, FileDown, MessageSquare } from "lucide-react";
import { api, fmtUtc, RunDetail as TRunDetail } from "../lib/api";
import { usePoll } from "../hooks/usePoll";
import StageChip from "../components/StageChip";
import ScoreCard from "../components/ScoreCard";

const STAGES = ["recon", "analyst", "exploit", "patch", "report"];
const TERMINAL = new Set(["done", "error", "aborted"]);

export default function RunDetail() {
  const { runId = "" } = useParams();
  const [busy, setBusy] = useState<string | null>(null);

  const { data, error } = usePoll<TRunDetail>(
    () => api.run(runId),
    2000,
    [runId],
    (d) => TERMINAL.has(d.status.current_stage),
  );

  if (error) return <div className="card text-bad">Error: {error}</div>;
  if (!data) return <div className="card">Loading…</div>;

  const { status, artifacts, log, tokens } = data;
  const idx = STAGES.indexOf(status.current_stage);
  const hasScore = artifacts.includes("06_score.json");
  const hasReportMd = artifacts.some((a) => /^05_report_.*\.md$/.test(a) && !a.endsWith("_eli5.md"));

  async function decide(decision: "approve" | "abort") {
    if (!status.pending_gate) return;
    setBusy(decision);
    try {
      await api.decideGate(runId, status.pending_gate, decision);
    } catch (e) {
      alert(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="card">
      <h1 className="text-xl font-semibold mb-2 text-fg">Run <code>{status.run_id}</code></h1>

      <div className="flex flex-wrap gap-x-8 gap-y-2 text-sm pb-4 mb-4 border-b border-border text-fg-muted">
        <div><strong className="text-fg">Target:</strong> {status.target}</div>
        {status.repo && <div><strong className="text-fg">Repo:</strong> <code>{status.repo}</code></div>}
        <div><strong className="text-fg">Started:</strong> {fmtUtc(status.started_at)}</div>
        {status.stop_after && <div><strong className="text-fg">Stop after:</strong> {status.stop_after}</div>}
      </div>

      <div className="flex items-center gap-2 flex-wrap mb-4 text-sm">
        <strong>Status:</strong>
        <StageChip stage={status.current_stage} />
        {status.auto_approve && <span className="pill">auto-approve</span>}
        {status.finished_at && <span className="text-fg-dim">finished {fmtUtc(status.finished_at)}</span>}
      </div>

      {status.error && <pre className="code text-bad bg-bad-soft border-bad/40">{status.error}</pre>}

      {status.pending_gate && (
        <div
          className="rounded-xl p-5 mb-4 border shadow-soft"
          style={{
            background: "linear-gradient(135deg, var(--warn-soft), color-mix(in srgb, var(--warn-soft) 60%, transparent))",
            borderColor: "color-mix(in srgb, var(--warn) 35%, var(--border))",
          }}
        >
          <div className="font-semibold mb-2 flex items-center gap-2 text-fg">
            <Pause size={16} /> Human gate: <code>{status.pending_gate}</code>
          </div>
          <p className="text-fg-muted">{status.pending_gate_prompt}</p>
          <div className="flex gap-3 mt-3">
            <button
              disabled={!!busy}
              onClick={() => decide("approve")}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg font-medium text-sm text-white bg-ok transition-all duration-150 hover:-translate-y-0.5 disabled:opacity-50"
            >
              <Check size={16} /> Approve
            </button>
            <button
              disabled={!!busy}
              onClick={() => decide("abort")}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg font-medium text-sm text-white bg-bad transition-all duration-150 hover:-translate-y-0.5 disabled:opacity-50"
            >
              <X size={16} /> Abort
            </button>
          </div>
        </div>
      )}

      <ol className="flex gap-2 flex-wrap p-0 my-4 list-none">
        {STAGES.map((s, i) => {
          const done = status.current_stage === "done" || idx > i;
          const active = status.current_stage === s && !status.pending_gate;
          return (
            <li
              key={s}
              className={[
                "flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm border transition-all duration-150",
                active
                  ? "bg-accent-soft text-accent border-accent/40"
                  : done
                    ? "bg-bg-soft text-ok border-ok/40"
                    : "bg-bg-soft text-fg-muted border-border",
              ].join(" ")}
            >
              <span>{done ? "✓" : active ? "●" : "○"}</span>
              <span>{i + 1}. {s.charAt(0).toUpperCase() + s.slice(1)}</span>
            </li>
          );
        })}
      </ol>

      {status.gate_history.length > 0 && (
        <>
          <H3>Gate history</H3>
          <ul className="m-0 p-0 list-none">
            {status.gate_history.map((g, i) => (
              <li key={i} className="py-1 text-sm flex items-center gap-2 flex-wrap">
                <code>{g.gate}</code>
                <span className={g.approved ? "text-ok" : "text-bad"}>{g.approved ? "approved" : "aborted"}</span>
                <span className="text-fg-dim">{fmtUtc(g.decided_at)}</span>
              </li>
            ))}
          </ul>
        </>
      )}

      {tokens && tokens.calls > 0 && (
        <>
          <H3>Tokens used</H3>
          <div className="flex items-baseline gap-2 flex-wrap rounded-xl px-4 py-3 text-sm bg-bg-soft border border-border text-fg-muted">
            <span className="text-xl font-semibold tabular-nums text-fg">{tokens.total.toLocaleString()}</span>
            <span className="text-fg-dim">total</span>
            <span className="text-border-strong">·</span>
            <span>{tokens.prompt.toLocaleString()} in</span>
            <span className="text-border-strong">+</span>
            <span>{tokens.completion.toLocaleString()} out</span>
            <span className="text-border-strong">·</span>
            <span>{tokens.calls} call{tokens.calls === 1 ? "" : "s"}</span>
          </div>
        </>
      )}

      {hasScore && (
        <>
          <H3>Score for this run</H3>
          <div className="rounded-xl px-4 py-4 bg-bg-soft border border-border">
            <ScoreCard runId={runId} compact />
          </div>
        </>
      )}

      <div className="flex flex-wrap gap-2 mt-4">
        {hasReportMd && (
          <a
            href={api.reportPdfUrl(runId)}
            target="_blank"
            rel="noopener noreferrer"
            className="btn btn-ghost text-sm py-1.5 px-3 inline-flex items-center gap-1.5"
          >
            <FileDown size={14} /> Download report PDF
          </a>
        )}
        <Link
          to={`/chat?run_id=${encodeURIComponent(runId)}`}
          className="btn btn-ghost text-sm py-1.5 px-3 inline-flex items-center gap-1.5"
        >
          <MessageSquare size={14} /> Ask AI about this run
        </Link>
      </div>

      <H3>Live log</H3>
      {log ? <pre className="log max-h-[380px]">{log}</pre> : <p className="text-fg-dim">No log output yet.</p>}

      <H3>Artifacts</H3>
      {artifacts.length === 0 ? (
        <p className="text-fg-dim">No artifacts yet — first stage still running.</p>
      ) : (
        <ul className="grid gap-1.5 list-none m-0 p-0">
          {artifacts.map((a) => (
            <li key={a} className="px-3.5 py-2 rounded-md bg-bg-soft border border-border">
              <Link to={`/runs/${runId}/artifact/${encodeURIComponent(a)}`} className="font-mono text-sm text-fg">
                {a}
              </Link>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function H3({ children }: { children: React.ReactNode }) {
  return <h3 className="text-xs uppercase tracking-wider mt-5 mb-2 text-fg-dim">{children}</h3>;
}
