import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft } from "lucide-react";
import { api, ArtifactPayload } from "../lib/api";

export default function Artifact() {
  const { runId = "", name = "" } = useParams();
  const [data, setData] = useState<ArtifactPayload | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.artifact(runId, decodeURIComponent(name)).then(setData).catch((e) => setError(String(e)));
  }, [runId, name]);

  if (error) return <div className="card text-bad">{error}</div>;
  if (!data) return <div className="card">Loading…</div>;

  return (
    <section className="card">
      <Link to={`/runs/${runId}`} className="inline-flex items-center gap-1.5 text-sm mb-3">
        <ArrowLeft size={14} /> Back to run
      </Link>
      <h1 className="text-xl font-semibold mb-1 text-fg"><code>{data.name}</code></h1>
      <p className="text-sm mb-4 text-fg-dim">
        Run <code>{data.run_id}</code> · kind: <code>{data.kind}</code>
      </p>

      {(data.kind === "report_md" || data.kind === "eli5_md") && data.html ? (
        <div className="prose-md" dangerouslySetInnerHTML={{ __html: data.html }} />
      ) : data.kind === "roadmap" && data.data ? (
        <RoadmapView data={data.data as RoadmapData} />
      ) : data.kind === "score" && data.data ? (
        <ScoreView data={data.data as ScoreData} />
      ) : data.kind === "secrets" && data.data ? (
        <SecretsView data={data.data as SecretsData} />
      ) : data.kind === "deps" && data.data ? (
        <DepsView data={data.data as DepsData} />
      ) : data.data !== undefined ? (
        <pre className="code">{JSON.stringify(data.data, null, 2)}</pre>
      ) : (
        <pre className="code">{data.raw}</pre>
      )}
    </section>
  );
}

type RoadmapItem = {
  rank: number; kind: string; title: string; file?: string; line_range?: string;
  cwe?: string; severity: string; exploitability: string;
  effort: string; fix_recommendation: string; priority_score: number;
};
type RoadmapData = { total: number; items: RoadmapItem[] };

function RoadmapView({ data }: { data: RoadmapData }) {
  if (!data.items || data.items.length === 0) {
    return <p className="text-fg-dim">No roadmap items.</p>;
  }
  return (
    <div className="overflow-x-auto">
      <table className="data-table">
        <thead>
          <tr>
            <th>#</th><th>Kind</th><th>Title</th><th>Severity</th>
            <th>Effort</th><th>Recommendation</th>
          </tr>
        </thead>
        <tbody>
          {data.items.map((it) => (
            <tr key={`${it.kind}-${it.rank}`}>
              <td className="tabular-nums">{it.rank}</td>
              <td><span className="pill">{it.kind}</span></td>
              <td>
                <div className="font-medium">{it.title}</div>
                {it.file && (
                  <div className="text-xs text-fg-dim font-mono">
                    {it.file}{it.line_range ? `:${it.line_range}` : ""}
                  </div>
                )}
              </td>
              <td><SeverityPill s={it.severity} /></td>
              <td className="text-fg-dim capitalize">{it.effort}</td>
              <td className="text-sm">{it.fix_recommendation}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

type ScoreData = {
  overall: number; grade: string; risk_band: string;
  categories: { name: string; score: number; issues: number; detail: string }[];
};
function ScoreView({ data }: { data: ScoreData }) {
  return (
    <div className="grid gap-4">
      <div className="flex items-center gap-4">
        <div className="text-5xl font-semibold tabular-nums">{data.overall}</div>
        <div>
          <div className="text-xl font-semibold">Grade {data.grade}</div>
          <div className="text-fg-dim capitalize">{data.risk_band} risk</div>
        </div>
      </div>
      <table className="data-table">
        <thead><tr><th>Category</th><th>Score</th><th>Issues</th><th>Detail</th></tr></thead>
        <tbody>
          {data.categories.map((c) => (
            <tr key={c.name}>
              <td className="capitalize">{c.name}</td>
              <td className="tabular-nums">{c.score}</td>
              <td className="tabular-nums">{c.issues}</td>
              <td className="text-fg-dim text-sm">{c.detail}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

type SecretsData = {
  total: number;
  by_confidence: Record<string, number>;
  hits: { id: string; description: string; confidence: string; file: string; line: number; snippet: string }[];
};
function SecretsView({ data }: { data: SecretsData }) {
  if (data.total === 0) return <p className="text-ok">No secrets matched any pattern.</p>;
  return (
    <div className="overflow-x-auto">
      <p className="text-fg-muted">
        <strong>{data.total}</strong> potential secret(s) — values are masked.
      </p>
      <table className="data-table">
        <thead><tr><th>Pattern</th><th>Confidence</th><th>File</th><th>Snippet</th></tr></thead>
        <tbody>
          {data.hits.map((h, i) => (
            <tr key={i}>
              <td>{h.description}</td>
              <td><SeverityPill s={h.confidence} /></td>
              <td className="font-mono text-xs">{h.file}:{h.line}</td>
              <td><code className="text-xs">{h.snippet}</code></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

type DepsData = {
  total: number;
  scanners_run: string[];
  scanners_unavailable: string[];
  vulnerabilities: { source: string; package: string; version: string; id: string; summary: string; severity: string; fixed_in: string }[];
};
function DepsView({ data }: { data: DepsData }) {
  if (!data.scanners_run || data.scanners_run.length === 0) {
    return (
      <div>
        <p className="text-fg-muted">
          No dependency scanner is installed. To enable: install <code>osv-scanner</code> or
          <code> pip-audit</code> on the server, then re-run.
        </p>
        {data.scanners_unavailable && (
          <p className="text-xs text-fg-dim">Tried: {data.scanners_unavailable.join(", ")}</p>
        )}
      </div>
    );
  }
  if (data.total === 0) return <p className="text-ok">No known vulnerable dependencies.</p>;
  return (
    <div className="overflow-x-auto">
      <p className="text-fg-muted">
        <strong>{data.total}</strong> vulnerable dependency version(s)
        — scanners: {data.scanners_run.join(", ")}
      </p>
      <table className="data-table">
        <thead><tr><th>Package</th><th>Version</th><th>ID</th><th>Severity</th><th>Fix</th><th>Summary</th></tr></thead>
        <tbody>
          {data.vulnerabilities.map((v, i) => (
            <tr key={i}>
              <td className="font-mono">{v.package}</td>
              <td className="font-mono">{v.version}</td>
              <td className="font-mono text-xs">{v.id}</td>
              <td><SeverityPill s={v.severity} /></td>
              <td className="font-mono text-xs">{v.fixed_in || "—"}</td>
              <td className="text-sm">{v.summary}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SeverityPill({ s }: { s: string }) {
  const norm = (s || "unknown").toLowerCase();
  const cls =
    norm === "critical" || norm === "high" ? "bg-bad-soft text-bad border-bad/40" :
    norm === "medium" || norm === "moderate" ? "bg-warn-soft text-warn border-warn/40" :
    norm === "low" ? "bg-bg-soft text-fg-muted border-border" :
    "bg-bg-soft text-fg-dim border-border";
  return <span className={`pill capitalize border ${cls}`}>{s || "unknown"}</span>;
}
