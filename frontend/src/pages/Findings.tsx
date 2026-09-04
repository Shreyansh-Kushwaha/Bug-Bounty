import { FormEvent, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, DuplicateGroup, Finding } from "../lib/api";
import { SevChip } from "../components/StageChip";
import { EmptyState, ErrorBanner } from "../components/states";

export default function Findings() {
  const [params, setParams] = useSearchParams();
  const target = params.get("target");
  const [rows, setRows] = useState<Finding[]>([]);
  const [dupes, setDupes] = useState<DuplicateGroup[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.findings(target).then((r) => setRows(r.findings)).catch((e) => setError(String(e)));
  }, [target]);

  useEffect(() => {
    api.triage().then((r) => setDupes(r.duplicates)).catch(() => setDupes([]));
  }, []);

  function onFilter(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const t = (new FormData(e.currentTarget).get("target") || "").toString().trim();
    setParams(t ? { target: t } : {});
  }

  return (
    <section className="card">
      <h1 className="text-2xl font-semibold mb-4 text-fg">
        Findings
        {target && <span className="ml-2 text-sm font-normal text-fg-dim">· filter: {target}</span>}
      </h1>

      <form onSubmit={onFilter} className="flex gap-2 items-center mb-4 flex-wrap">
        <input name="target" defaultValue={target || ""} placeholder="target name" className="input max-w-[260px]" />
        <button type="submit" className="btn">Filter</button>
        {target && <Link to="/findings" className="btn btn-ghost">Clear</Link>}
      </form>

      {error && <div className="mb-4"><ErrorBanner message={error} /></div>}

      {dupes.length > 0 && (
        <div className="mb-5 rounded-xl border border-warn/40 bg-warn-soft p-4">
          <div className="font-semibold text-fg mb-2">
            {dupes.length} duplicate finding group{dupes.length === 1 ? "" : "s"} across runs
          </div>
          <ul className="grid gap-2 m-0 p-0 list-none">
            {dupes.map((g) => (
              <li key={g.dedupe_key} className="text-sm flex items-center gap-2 flex-wrap">
                <span className="pill">{g.count}×</span>
                <code className="text-xs">{g.dedupe_key}</code>
                <span className="text-fg-dim">
                  {g.findings.map((f) => f.run_id).join(", ")}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {rows.length === 0 ? (
        <EmptyState title="No findings yet" hint="Findings appear here once a run reaches the exploit stage." />
      ) : (
        <div className="overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                {["Run", "Target", "Hypothesis", "CWE", "Severity", "Validated", "Patch", "Report", "Title"].map((h) => (
                  <th key={h}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((f, i) => (
                <tr key={i}>
                  <td><Link to={`/runs/${f.run_id}`}>{f.run_id}</Link></td>
                  <td>{f.target}</td>
                  <td>{f.hypothesis_id}</td>
                  <td>{f.cwe || "—"}</td>
                  <td><SevChip severity={f.severity} /></td>
                  <td>{f.validated ? "✓" : "—"}</td>
                  <td>{f.has_patch ? "✓" : "—"}</td>
                  <td>{f.has_report ? "✓" : "—"}</td>
                  <td>{f.title || ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
