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

      {data.kind === "report_md" && data.html ? (
        <div className="prose-md" dangerouslySetInnerHTML={{ __html: data.html }} />
      ) : data.data !== undefined ? (
        <pre className="code">{JSON.stringify(data.data, null, 2)}</pre>
      ) : (
        <pre className="code">{data.raw}</pre>
      )}
    </section>
  );
}
