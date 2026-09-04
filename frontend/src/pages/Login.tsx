import { FormEvent, useState } from "react";
import { Shield } from "lucide-react";
import { api } from "../lib/api";
import { useAuth } from "../hooks/useAuth";

export default function Login() {
  const { refresh } = useAuth();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    const password = String(new FormData(e.currentTarget).get("password") || "");
    try {
      await api.login(password);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-screen grid place-items-center px-6 bg-bg">
      <div className="w-full max-w-sm">
        <div className="flex items-center gap-2 justify-center mb-6 font-semibold text-fg">
          <span
            className="grid place-items-center w-8 h-8 rounded-md text-white"
            style={{ background: "linear-gradient(135deg, var(--accent), var(--accent-hover))" }}
            aria-hidden
          >
            <Shield size={18} strokeWidth={2.4} />
          </span>
          <span className="text-lg">Bug-Bounty</span>
        </div>

        <form onSubmit={onSubmit} className="card grid gap-4">
          <div>
            <h1 className="text-lg font-semibold text-fg mb-1">Operator sign in</h1>
            <p className="text-sm text-fg-muted m-0">Enter the operator password to continue.</p>
          </div>
          <label className="block">
            <span className="block text-xs font-medium mb-1.5 text-fg-muted">Password</span>
            <input
              type="password"
              name="password"
              required
              autoFocus
              className="input"
              placeholder="••••••••"
            />
          </label>
          {error && <div className="text-sm text-bad" role="alert">{error}</div>}
          <button type="submit" disabled={busy} className="btn">
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>
      </div>
    </div>
  );
}
