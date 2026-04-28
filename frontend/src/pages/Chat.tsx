import { FormEvent, useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, ChatResponse } from "../lib/api";
import { Field, PageHeader, SectionHead } from "../components/ui";

type Turn = {
  role: "user" | "assistant";
  text: string;
  meta?: ChatResponse["context_used"] | null;
  model?: string | null;
};

export default function Chat() {
  const [params, setParams] = useSearchParams();
  const [runId, setRunId] = useState<string>(params.get("run_id") || "");
  const [turns, setTurns] = useState<Turn[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Keep ?run_id= in the URL in sync so the panel is shareable.
  useEffect(() => {
    if (runId) {
      params.set("run_id", runId);
    } else {
      params.delete("run_id");
    }
    setParams(params, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runId]);

  async function onAsk(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    const form = new FormData(e.currentTarget);
    const q = String(form.get("question") || "").trim();
    if (!q) return;

    setTurns((t) => [...t, { role: "user", text: q }]);
    setBusy(true);
    try {
      const res = await api.chat(q, runId || null);
      setTurns((t) => [...t, {
        role: "assistant",
        text: res.answer,
        meta: res.context_used,
        model: res.model,
      }]);
      e.currentTarget.reset();
      inputRef.current?.focus();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="Ask Security AI"
        title="Ask anything about your scan results"
        body="Grounded in your findings DB and (optionally) a specific run's artifacts. Each answer is one-shot — no memory between questions."
      />

      <section className="card mb-4">
        <Field label="Run context (optional — leave blank to query across all runs)">
          <input
            type="text"
            placeholder="e.g. demo-repo_1714230000"
            value={runId}
            onChange={(e) => setRunId(e.target.value.trim())}
            className="input font-mono text-sm"
          />
        </Field>
      </section>

      <section className="card mb-4">
        <SectionHead title="Conversation" />
        {turns.length === 0 ? (
          <p className="text-fg-dim m-0">Try: <em>"What's my biggest risk?"</em>, <em>"How do I fix the JWT issue?"</em>, <em>"Explain the top finding in plain English."</em></p>
        ) : (
          <div className="grid gap-3">
            {turns.map((t, i) => (
              <div
                key={i}
                className={`p-3.5 rounded-lg border ${
                  t.role === "user"
                    ? "bg-accent-soft border-accent/30"
                    : "bg-bg-soft border-border"
                }`}
              >
                <div className="text-xs uppercase tracking-wider text-fg-dim mb-1">
                  {t.role === "user" ? "You" : `Assistant${t.model ? ` · ${t.model}` : ""}`}
                </div>
                <div className="whitespace-pre-wrap text-sm">{t.text}</div>
                {t.meta && (
                  <div className="text-xs text-fg-dim mt-2">
                    grounded in {t.meta.findings_count} finding(s)
                    {t.meta.has_report && " + report"}
                    {t.meta.has_score && " + score"}
                    {t.meta.run_id && <> · run <code>{t.meta.run_id}</code></>}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </section>

      {error && (
        <div className="card mb-4 bg-bad-soft border-bad text-bad">{error}</div>
      )}

      <section className="card">
        <form onSubmit={onAsk} className="grid gap-3">
          <Field label="Your question">
            <input
              ref={inputRef}
              type="text"
              name="question"
              required
              maxLength={2000}
              autoFocus
              placeholder="Why is this critical?"
              className="input"
            />
          </Field>
          <div>
            <button type="submit" disabled={busy} className="btn">
              {busy ? "Thinking…" : "Ask"}
            </button>
          </div>
        </form>
      </section>
    </>
  );
}
