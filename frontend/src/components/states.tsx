// Shared loading / empty / error presentational states so pages are consistent.
import { AlertTriangle, Inbox, Loader2 } from "lucide-react";

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 text-fg-dim py-6" role="status" aria-live="polite">
      <Loader2 size={16} className="animate-spin" />
      <span>{label}</span>
    </div>
  );
}

export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center text-center gap-2 py-10 text-fg-dim">
      <Inbox size={28} strokeWidth={1.5} />
      <div className="font-medium text-fg-muted">{title}</div>
      {hint && <div className="text-sm max-w-sm">{hint}</div>}
    </div>
  );
}

export function ErrorBanner({ message }: { message: string }) {
  return (
    <div
      className="card bg-bad-soft border-bad text-bad flex items-start gap-2"
      role="alert"
    >
      <AlertTriangle size={16} className="mt-0.5 shrink-0" />
      <span>{message}</span>
    </div>
  );
}
