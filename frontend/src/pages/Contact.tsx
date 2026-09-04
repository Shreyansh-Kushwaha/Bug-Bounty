import { useState } from "react";
import { PageHeader } from "../components/ui";

const GITHUB = "https://github.com/Shreyansh-Kushwaha/Bug-Bounty";

const faqs = [
  { q: "How do I add my repo to the allowlist?",
    a: "Open a PR adding an entry to config/targets.json with the repo URL, ref, category, and a note. Your handle is recorded in the audit log on first submission." },
  { q: "Will the pipeline submit reports for me?",
    a: "No. The Report stage writes a Markdown file to disk. It never makes HTTP calls to bug-bounty platforms — disclosure is your decision." },
  { q: "What happens if Docker isn't available?",
    a: "Exploit validation is skipped. The pipeline still proceeds to Patch and Report — the PoC is recorded as unexecuted, and that fact appears in the report." },
  { q: "Which models does it use?",
    a: "Three tiers (fast / reasoning / coder). Default primary is gemini-3-flash-preview, falling back to gemini-2.5-flash and gemini-2.5-flash-lite. Groq and OpenRouter are optional fallback providers." },
];

export default function Contact() {
  const [open, setOpen] = useState<number | null>(null);

  return (
    <>
      <PageHeader
        eyebrow="Contact"
        title="Get in touch"
        body="Questions, suggestions, or want to nominate a target for the allowlist? Drop a note — we read everything."
      />

      <div className="grid lg:grid-cols-3 gap-5">
        <section className="card lg:col-span-2">
          <h2 className="text-lg font-semibold mb-3 text-fg">Open an issue or discussion</h2>
          <p className="text-sm text-fg-muted mb-4">
            The fastest way to reach the maintainer is on GitHub. Questions, target
            nominations, and bug reports all live in the repository.
          </p>
          <div className="flex flex-wrap gap-3">
            <a href={`${GITHUB}/issues/new`} target="_blank" rel="noopener noreferrer" className="btn">
              New issue on GitHub
            </a>
            <a href={`${GITHUB}/discussions`} target="_blank" rel="noopener noreferrer" className="btn btn-secondary">
              Start a discussion
            </a>
          </div>
          <p className="text-xs mt-4 text-fg-dim">
            For a security disclosure, please open a private security advisory in the
            repository rather than a public issue.
          </p>
        </section>

        <aside className="card">
          <h2 className="text-lg font-semibold mb-3 text-fg">Other ways</h2>
          <ul className="m-0 p-0 list-none grid gap-3">
            <li>
              <Sub>GitHub</Sub>
              <a href={GITHUB} target="_blank" rel="noopener noreferrer">github.com/Shreyansh-Kushwaha</a>
            </li>
            <li>
              <Sub>Security disclosure</Sub>
              <a href={`${GITHUB}/security/advisories/new`} target="_blank" rel="noopener noreferrer">
                Private advisory
              </a>
            </li>
          </ul>
          <h3 className="mt-5 mb-1 text-base font-semibold text-fg">Response time</h3>
          <p className="text-sm text-fg-muted">
            This is a personal research project, so replies are best-effort. Security
            reports are prioritized.
          </p>
        </aside>
      </div>

      <section className="card mt-5">
        <h2 className="text-lg font-semibold mb-2 text-fg">Frequently asked</h2>
        <div className="grid gap-1">
          {faqs.map((f, i) => (
            <div key={i} className="border-b last:border-b-0 border-border py-1">
              <button
                onClick={() => setOpen(open === i ? null : i)}
                className="w-full text-left py-2 flex items-center justify-between text-accent"
              >
                <span>{f.q}</span>
                <span className="text-fg-dim">{open === i ? "−" : "+"}</span>
              </button>
              {open === i && <p className="pb-2 text-sm text-fg-muted">{f.a}</p>}
            </div>
          ))}
        </div>
      </section>
    </>
  );
}

function Sub({ children }: { children: React.ReactNode }) {
  return <div className="text-[11px] uppercase tracking-wider text-fg-dim">{children}</div>;
}
