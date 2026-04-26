import { Link } from "react-router-dom";
import { Shield } from "lucide-react";

export default function Footer() {
  const year = new Date().getFullYear();
  return (
    <footer className="mt-16 px-6 pt-10 pb-8 text-sm bg-bg-elev border-t border-border text-fg-muted">
      <div className="max-w-site mx-auto grid gap-8 grid-cols-1 sm:grid-cols-2 md:grid-cols-[1.4fr_repeat(3,1fr)]">
        <div>
          <div className="flex items-center gap-2 font-semibold mb-3 text-fg">
            <span
              className="grid place-items-center w-7 h-7 rounded-md text-white"
              style={{ background: "linear-gradient(135deg, var(--accent), var(--accent-hover))" }}
              aria-hidden
            >
              <Shield size={16} strokeWidth={2.4} />
            </span>
            <span>Bug-Bounty Pipeline</span>
          </div>
          <p className="max-w-xs leading-relaxed m-0">
            An AI-driven security research platform for authorized open-source repositories. Recon → Patch in five
            stages.
          </p>
        </div>

        <FCol title="Product">
          <FLink to="/features">Features</FLink>
          <FLink to="/dashboard">Dashboard</FLink>
          <FLink to="/findings">Findings</FLink>
          <FLink to="/audit">Audit log</FLink>
        </FCol>

        <FCol title="Resources">
          <FLink to="/about">About</FLink>
          <a href="https://github.com/" rel="noopener" className="hover:text-fg">GitHub</a>
          <FLink to="/contact">Contact</FLink>
        </FCol>

        <FCol title="Safety">
          <span>Allowlist-only targeting</span>
          <span>Non-destructive PoCs</span>
          <span>No auto-submission</span>
          <span>Hash-chained audit log</span>
        </FCol>
      </div>

      <div className="max-w-site mx-auto mt-8 pt-6 flex flex-wrap justify-between gap-2 text-xs text-fg-dim border-t border-border">
        <span>© {year} Bug-Bounty Pipeline. Runs are scoped to the authorized allowlist.</span>
        <span>Built with FastAPI · Gemini · React</span>
      </div>
    </footer>
  );
}

function FCol({ title, children }: { title: string; children: React.ReactNode }) {
  const items = Array.isArray(children) ? children : [children];
  return (
    <div>
      <h4 className="text-xs uppercase tracking-wider mb-3 font-semibold text-fg-dim">{title}</h4>
      <ul className="grid gap-2 list-none p-0 m-0">
        {items.map((c, i) => <li key={i}>{c}</li>)}
      </ul>
    </div>
  );
}

function FLink({ to, children }: { to: string; children: React.ReactNode }) {
  return (
    <Link to={to} className="text-fg-muted hover:text-fg">
      {children}
    </Link>
  );
}
