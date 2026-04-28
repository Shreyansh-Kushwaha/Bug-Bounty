// Tiny JSON client. In dev, /api is proxied to FastAPI by vite.config.ts.
// In prod, the React build is served at /app and /api hits the same origin.

export type Target = {
  name: string;
  repo: string;
  ref: string;
  category: string;
  notes?: string;
  known_cve?: string | null;
};

export type GateEntry = {
  gate: string;
  prompt: string;
  approved: boolean;
  decided_at: number;
};

export type RunStatus = {
  run_id: string;
  target: string;
  started_at: number;
  finished_at: number | null;
  current_stage: string;
  stop_after: string | null;
  auto_approve: boolean;
  error: string | null;
  repo: string;
  pending_gate: string | null;
  pending_gate_prompt: string;
  gate_history: GateEntry[];
};

export type QuotaRow = {
  model: string;
  calls: number;
  prompt: number;
  completion: number;
  total: number;
  limit: number | null;
  pct: number;
  warn: boolean;
};

export type Finding = {
  run_id: string;
  target: string;
  hypothesis_id: string;
  cwe?: string | null;
  severity?: string | null;
  validated?: boolean | number;
  has_patch?: boolean | number;
  has_report?: boolean | number;
  title?: string | null;
};

export type AuditEntry = {
  ts: number;
  event: string;
  payload: Record<string, unknown>;
};

export type Tokens = {
  calls: number;
  prompt: number;
  completion: number;
  total: number;
  by_model?: { model: string; calls: number; total: number }[];
};

export type RunDetail = {
  status: RunStatus;
  artifacts: string[];
  log: string;
  tokens: Tokens;
};

export type ArtifactPayload = {
  name: string;
  run_id: string;
  kind: string;
  data?: unknown;
  raw?: string;
  html?: string;
};

export type CategoryScore = {
  name: string;
  score: number;
  issues: number;
  detail: string;
};

export type SecurityScore = {
  overall: number;
  grade: string;
  risk_band: string;
  categories: CategoryScore[];
};

export type ScoreResponse = {
  score: SecurityScore;
  scope: "run" | "all";
  run_id?: string;
  findings_counted?: number;
};

export type ChatResponse = {
  answer: string;
  model: string | null;
  provider: string | null;
  context_used: {
    run_id: string | null;
    findings_count: number;
    has_report: boolean;
    has_score: boolean;
  } | null;
};

async function jget<T>(path: string): Promise<T> {
  const r = await fetch(path, { headers: { Accept: "application/json" } });
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}: ${path}`);
  return r.json() as Promise<T>;
}

async function jpost<T>(path: string, body: unknown): Promise<T> {
  const r = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    let detail = `${r.status} ${r.statusText}`;
    try {
      const j = await r.json();
      if (j && typeof j === "object" && "detail" in j) detail = String((j as { detail: unknown }).detail);
    } catch {}
    throw new Error(detail);
  }
  return r.json() as Promise<T>;
}

export const api = {
  targets: () => jget<{ targets: Target[] }>("/api/targets"),
  quota:   () => jget<{ quota: QuotaRow[] }>("/api/quota"),
  runs:    (limit = 20) => jget<{ runs: RunStatus[] }>(`/api/runs?limit=${limit}`),
  run:     (id: string) => jget<RunDetail>(`/api/runs/${encodeURIComponent(id)}`),
  artifact: (id: string, name: string) =>
    jget<ArtifactPayload>(`/api/runs/${encodeURIComponent(id)}/artifact/${encodeURIComponent(name)}`),
  findings: (target?: string | null) =>
    jget<{ findings: Finding[]; target_filter: string | null }>(
      target ? `/api/findings?target=${encodeURIComponent(target)}` : "/api/findings",
    ),
  audit: (limit = 200) =>
    jget<{ entries: AuditEntry[]; total: number; chain_ok: boolean; broken_line: number | null }>(
      `/api/audit?limit=${limit}`,
    ),
  createRun: (payload: {
    repo_url: string;
    ref: string;
    stop_after?: string;
    attested: boolean;
    attested_by?: string;
    notes?: string;
    auto_approve?: boolean;
  }) => jpost<{ run_id: string }>("/api/runs", payload),
  decideGate: (id: string, gate: string, decision: "approve" | "abort") =>
    jpost<{ ok: boolean }>(`/api/runs/${encodeURIComponent(id)}/gate`, { gate, decision }),
  score: (runId?: string) =>
    jget<ScoreResponse>(runId ? `/api/score?run_id=${encodeURIComponent(runId)}` : "/api/score"),
  chat: (question: string, runId?: string | null) =>
    jpost<ChatResponse>("/api/chat", { question, run_id: runId || undefined }),
  reportPdfUrl: (runId: string) =>
    `/api/runs/${encodeURIComponent(runId)}/report.pdf`,
};

export function fmtUtc(ts: number | null | undefined): string {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  const pad = (n: number) => n.toString().padStart(2, "0");
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`;
}
