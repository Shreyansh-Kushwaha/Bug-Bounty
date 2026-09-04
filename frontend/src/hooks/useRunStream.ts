import { useEffect, useRef, useState } from "react";
import { api, RunDetail } from "../lib/api";

const TERMINAL = new Set(["done", "error", "aborted"]);

/**
 * Live run detail via Server-Sent Events, with a polling fallback.
 *
 * SSE delivers status + log cheaply. Artifacts and token totals change less
 * often, so we refetch the full detail once on mount and again whenever the
 * stage changes. If EventSource is unavailable or errors, we fall back to
 * polling the full detail endpoint.
 */
export function useRunStream(runId: string) {
  const [data, setData] = useState<RunDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const stageRef = useRef<string>("");

  useEffect(() => {
    let closed = false;
    let es: EventSource | null = null;
    let pollTimer: number | null = null;

    const fullRefresh = async () => {
      try {
        const d = await api.run(runId);
        if (!closed) {
          setData(d);
          stageRef.current = d.status.current_stage;
        }
      } catch (e) {
        if (!closed) setError(e instanceof Error ? e.message : String(e));
      }
    };

    const startPolling = () => {
      if (pollTimer !== null) return;
      const tick = async () => {
        if (closed) return;
        await fullRefresh();
        if (!closed && !TERMINAL.has(stageRef.current)) {
          pollTimer = window.setTimeout(tick, 2500);
        }
      };
      tick();
    };

    // Initial full load, then attach the stream.
    fullRefresh();

    if (typeof EventSource !== "undefined") {
      try {
        es = new EventSource(api.eventsUrl(runId));
        es.onmessage = (ev) => {
          if (closed) return;
          try {
            const msg = JSON.parse(ev.data) as { status?: RunDetail["status"]; log?: string; error?: string };
            if (msg.error) return;
            setData((prev) => {
              const base = prev ?? { status: msg.status!, artifacts: [], log: "", tokens: { calls: 0, prompt: 0, completion: 0, total: 0 } };
              const nextStage = msg.status?.current_stage ?? base.status.current_stage;
              if (nextStage !== stageRef.current) {
                stageRef.current = nextStage;
                // Stage changed: pull fresh artifacts/tokens.
                fullRefresh();
              }
              return {
                ...base,
                status: msg.status ?? base.status,
                log: msg.log ?? base.log,
              };
            });
          } catch {
            /* ignore malformed frame */
          }
        };
        es.onerror = () => {
          es?.close();
          es = null;
          if (!closed) startPolling();
        };
      } catch {
        startPolling();
      }
    } else {
      startPolling();
    }

    return () => {
      closed = true;
      es?.close();
      if (pollTimer !== null) window.clearTimeout(pollTimer);
    };
  }, [runId]);

  return { data, error };
}
