import { useEffect, useRef, useState } from "react";

/**
 * Polls an async function on an interval. Stops when `stop` returns true.
 * Returns the latest data + error + loading state.
 */
export function usePoll<T>(
  fn: () => Promise<T>,
  intervalMs: number,
  deps: unknown[] = [],
  stop?: (data: T) => boolean,
) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const timer = useRef<number | null>(null);
  const cancelled = useRef(false);

  useEffect(() => {
    cancelled.current = false;
    let active = true;

    async function tick() {
      try {
        const next = await fn();
        if (!active) return;
        setData(next);
        setError(null);
        setLoading(false);
        if (stop && stop(next)) return;
      } catch (e) {
        if (!active) return;
        setError(e instanceof Error ? e.message : String(e));
        setLoading(false);
      }
      if (active && !cancelled.current) {
        timer.current = window.setTimeout(tick, intervalMs);
      }
    }
    tick();

    return () => {
      active = false;
      cancelled.current = true;
      if (timer.current) window.clearTimeout(timer.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { data, error, loading };
}
