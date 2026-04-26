import { useEffect, useState } from "react";
import { api, AuditEntry, fmtUtc } from "../lib/api";

type AuditData = {
  entries: AuditEntry[];
  total: number;
  chain_ok: boolean;
  broken_line: number | null;
};

export default function Audit() {
  const [data, setData] = useState<AuditData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.audit(200).then(setData).catch((e) => setError(String(e)));
  }, []);

  if (error) return <div className="card text-bad">{error}</div>;
  if (!data) return <div className="card">Loading…</div>;

  return (
    <section className="card">
      <h1 className="text-2xl font-semibold mb-3 text-fg">Audit log</h1>
      <p className="text-sm text-fg-muted">
        Chain status:{" "}
        {data.chain_ok ? (
          <strong className="text-ok">intact</strong>
        ) : (
          <strong className="text-bad">BROKEN at line {data.broken_line}</strong>
        )}
        {" · "}{data.total} entries · showing most recent {data.entries.length}.
      </p>

      <div className="overflow-x-auto mt-3">
        <table className="data-table">
          <thead>
            <tr>{["When", "Event", "Payload"].map((h) => <th key={h}>{h}</th>)}</tr>
          </thead>
          <tbody>
            {data.entries.map((e, i) => (
              <tr key={i}>
                <td className="whitespace-nowrap text-fg-dim">{fmtUtc(e.ts)}</td>
                <td><code>{e.event}</code></td>
                <td>
                  <pre className="code m-0 max-h-[220px]">{JSON.stringify(e.payload, null, 2)}</pre>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
