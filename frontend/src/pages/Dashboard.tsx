import { FormEvent, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, fmtUtc, QuotaRow, RunStatus, Target } from "../lib/api";
import StageChip from "../components/StageChip";
import { Field, SectionHead } from "../components/ui";

export default function Dashboard() {
  const nav = useNavigate();
  const [targets, setTargets] = useState<Target[]>([]);
  const [runs, setRuns] = useState<RunStatus[]>([]);
  const [quota, setQuota] = useState<QuotaRow[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = async () => {
    try {
      const [t, r, q] = await Promise.all([api.targets(), api.runs(20), api.quota()]);
      setTargets(t.targets);
      setRuns(r.runs);
      setQuota(q.quota);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  useEffect(() => {
    refresh();
    const id = window.setInterval(refresh, 5000);
    return () => window.clearInterval(id);
  }, []);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    const form = new FormData(e.currentTarget);
    try {
      const res = await api.createRun({
        repo_url: String(form.get("repo_url") || ""),
        ref: String(form.get("ref") || "main"),
        stop_after: String(form.get("stop_after") || ""),
        attested: form.get("attested") === "yes",
        attested_by: String(form.get("attested_by") || ""),
        notes: String(form.get("notes") || ""),
        auto_approve: form.get("auto_approve") === "yes",
      });
      nav(`/runs/${res.run_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
      <div className="mb-6">
        <span className="eyebrow">Dashboard</span>
        <h1 className="text-2xl font-semibold mb-1 text-fg">Start a new run</h1>
        <p className="m-0 text-fg-muted">
          Spin up a recon → report run against an authorized target. Live progress, gate approvals, and artifacts land here.
        </p>
      </div>

      {error && (
        <div className="card mb-4 bg-bad-soft border-bad text-bad">
          {error}
        </div>
      )}

      <section className="card mb-5">
        <form onSubmit={onSubmit} className="grid gap-4">
          <Field label="Repository URL">
            <input type="url" name="repo_url" required placeholder="https://github.com/you/your-repo.git" className="input" />
          </Field>

          <div className="grid sm:grid-cols-2 gap-4">
            <Field label="Ref (branch / tag / commit)">
              <input type="text" name="ref" defaultValue="main" className="input" />
            </Field>
            <Field label="Stop after">
              <select name="stop_after" defaultValue="" className="input">
                <option value="">Full pipeline (Recon → Report)</option>
                <option value="recon">Recon only</option>
                <option value="analyst">Analyst (stop before exploit)</option>
                <option value="exploit">Exploit</option>
                <option value="patch">Patch</option>
              </select>
            </Field>
          </div>

          <div className="grid sm:grid-cols-2 gap-4">
            <Field label="Your name / handle (for audit)">
              <input type="text" name="attested_by" placeholder="e.g. shreyansh" className="input" />
            </Field>
            <Field label="Notes (optional)">
              <input type="text" name="notes" placeholder="e.g. 'personal side project'" className="input" />
            </Field>
          </div>

          <label className="flex gap-3 items-start p-3 rounded-lg bg-accent-soft border border-border">
            <input type="checkbox" name="attested" value="yes" required className="mt-1" />
            <span className="text-sm text-fg-muted">
              I confirm I own this repository, or I have written permission from the owner to test it for security issues.
              This statement will be recorded in the audit log.
            </span>
          </label>

          <label className="flex gap-3 items-start p-3 rounded-lg bg-bg-soft border border-border">
            <input type="checkbox" name="auto_approve" value="yes" className="mt-1" />
            <span className="text-sm text-fg-muted">
              Auto-approve all human gates (skips Approve/Abort prompts before Exploit and Patch stages). Only for testing.
            </span>
          </label>

          <div>
            <button type="submit" disabled={submitting} className="btn">
              {submitting ? "Starting…" : "Start run"}
            </button>
          </div>
        </form>
      </section>

      <section className="card mb-5">
        <SectionHead title="Today's LLM usage" hint="UTC" />
        {quota.length === 0 ? (
          <p className="text-fg-dim">No usage recorded yet today.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr><th>Model</th><th>Requests today</th><th className="text-right">Tokens</th></tr>
              </thead>
              <tbody>
                {quota.map((q) => (
                  <tr key={q.model} className={q.warn ? "bg-bad-soft" : ""}>
                    <td><code>{q.model}</code></td>
                    <td>
                      {q.limit ? (
                        <>
                          <strong>{q.calls}/{q.limit}</strong>
                          <div className="h-1.5 rounded-full mt-1.5 overflow-hidden bg-bg-soft">
                            <span
                              className="block h-full transition-all duration-500"
                              style={{
                                width: `${Math.min(100, q.pct)}%`,
                                background: q.warn
                                  ? "linear-gradient(90deg, var(--warn), var(--bad))"
                                  : "linear-gradient(90deg, var(--ok), var(--accent))",
                              }}
                            />
                          </div>
                        </>
                      ) : q.calls}
                    </td>
                    <td className="text-right tabular-nums">{q.total.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="card mb-5">
        <SectionHead
          title="Recent runs"
          right={<Link to="/findings" className="btn btn-ghost text-sm py-1.5 px-3">Browse findings →</Link>}
        />
        {runs.length === 0 ? (
          <p className="text-fg-dim">No runs yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr><th>Run</th><th>Target</th><th>Stage</th><th>Started</th><th>Finished</th></tr>
              </thead>
              <tbody>
                {runs.map((r) => (
                  <tr key={r.run_id}>
                    <td><Link to={`/runs/${r.run_id}`}>{r.run_id}</Link></td>
                    <td>{r.target}</td>
                    <td><StageChip stage={r.current_stage} /></td>
                    <td className="text-fg-dim">{fmtUtc(r.started_at)}</td>
                    <td className="text-fg-dim">{fmtUtc(r.finished_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="card">
        <SectionHead title="Authorized targets" />
        <div className="overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr><th>Name</th><th>Repo</th><th>Ref</th><th>Category</th><th>Notes</th></tr>
            </thead>
            <tbody>
              {targets.map((t) => (
                <tr key={t.name}>
                  <td><strong>{t.name}</strong></td>
                  <td><code>{t.repo}</code></td>
                  <td>{t.ref}</td>
                  <td>{t.category}</td>
                  <td className="text-fg-dim">{t.notes || ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
