import { FormEvent, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, Finding } from "../lib/api";
import { SevChip } from "../components/StageChip";

export default function Findings() {
  const [params, setParams] = useSearchParams();
  const target = params.get("target");
  const [rows, setRows] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.findings(target).then((r) => setRows(r.findings)).catch((e) => setError(String(e)));
  }, [target]);

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

      {error && <div className="text-bad">{error}</div>}

      {rows.length === 0 ? (
        <p className="text-fg-dim">No findings yet.</p>
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
