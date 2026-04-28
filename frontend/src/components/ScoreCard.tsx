import { useEffect, useState } from "react";
import { api, ScoreResponse } from "../lib/api";

type Props = {
  runId?: string;
  /** Show a smaller variant on dense pages (RunDetail). */
  compact?: boolean;
};

export default function ScoreCard({ runId, compact = false }: Props) {
  const [data, setData] = useState<ScoreResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setError(null);
    api.score(runId).then(
      (d) => { if (!cancelled) setData(d); },
      (e) => { if (!cancelled) setError(e instanceof Error ? e.message : String(e)); },
    );
    return () => { cancelled = true; };
  }, [runId]);

  if (error) return <div className="text-sm text-fg-dim">No score: {error}</div>;
  if (!data) return <div className="text-sm text-fg-dim">Loading score…</div>;

  const { score, scope } = data;
  const overallColor =
    score.overall >= 80 ? "var(--ok)" :
    score.overall >= 60 ? "var(--warn)" : "var(--bad)";

  return (
    <div className={`grid gap-3 ${compact ? "" : "sm:grid-cols-[auto,1fr]"} items-start`}>
      <div className="flex items-center gap-4">
        <div
          className="rounded-full flex items-center justify-center font-semibold tabular-nums"
          style={{
            width: compact ? 56 : 80,
            height: compact ? 56 : 80,
            background: `conic-gradient(${overallColor} ${score.overall * 3.6}deg, var(--bg-soft) 0)`,
            color: "var(--fg)",
          }}
        >
          <span
            className="rounded-full bg-bg flex items-center justify-center"
            style={{ width: compact ? 44 : 64, height: compact ? 44 : 64 }}
          >
            {score.overall}
          </span>
        </div>
        <div>
          <div className="text-2xl font-semibold leading-none" style={{ color: overallColor }}>
            {score.grade}
          </div>
          <div className="text-xs text-fg-dim mt-1">
            {scope === "run" ? "this run" : "all findings"}
            {" · "}
            {score.risk_band}
          </div>
        </div>
      </div>

      <div className="grid gap-1.5">
        {score.categories.map((c) => (
          <div key={c.name} className="flex items-center gap-3 text-sm">
            <div className="w-32 capitalize text-fg-muted">{c.name}</div>
            <div className="flex-1 h-1.5 rounded-full bg-bg-soft overflow-hidden">
              <span
                className="block h-full"
                style={{
                  width: `${c.score}%`,
                  background:
                    c.score >= 80 ? "var(--ok)" :
                    c.score >= 60 ? "var(--warn)" : "var(--bad)",
                }}
              />
            </div>
            <div className="w-10 tabular-nums text-right text-fg-muted">{c.score}</div>
            <div className="w-14 text-xs text-fg-dim text-right">
              {c.issues > 0 ? `${c.issues} issue${c.issues === 1 ? "" : "s"}` : "clean"}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
