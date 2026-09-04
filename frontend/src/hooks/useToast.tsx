import { createContext, useCallback, useContext, useState } from "react";

type Toast = { id: number; text: string; kind: "ok" | "bad" };
type ToastCtx = { push: (text: string, kind?: "ok" | "bad") => void };

const Ctx = createContext<ToastCtx | null>(null);

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const push = useCallback((text: string, kind: "ok" | "bad" = "ok") => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, text, kind }]);
    window.setTimeout(() => {
      setToasts((t) => t.filter((x) => x.id !== id));
    }, 3500);
  }, []);

  return (
    <Ctx.Provider value={{ push }}>
      {children}
      <div className="fixed bottom-4 right-4 z-[100] flex flex-col gap-2" aria-live="polite">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`px-4 py-2.5 rounded-lg shadow-pop text-sm border ${
              t.kind === "ok"
                ? "bg-ok-soft border-ok/40 text-ok"
                : "bg-bad-soft border-bad/40 text-bad"
            }`}
            role="status"
          >
            {t.text}
          </div>
        ))}
      </div>
    </Ctx.Provider>
  );
}

export function useToast(): ToastCtx {
  const v = useContext(Ctx);
  if (!v) return { push: () => {} };
  return v;
}
