// Small presentational atoms used across pages.
// Keeping them here lets pages read like top-down content, not Tailwind soup.

export function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="block text-xs font-medium mb-1.5 text-fg-muted">{label}</span>
      {children}
    </label>
  );
}

export function SectionHead({
  title,
  hint,
  right,
}: {
  title: string;
  hint?: string;
  right?: React.ReactNode;
}) {
  return (
    <div className="flex items-baseline justify-between flex-wrap gap-2 mb-3">
      <h2 className="text-lg font-semibold m-0 text-fg">
        {title}
        {hint && <span className="ml-2 text-xs font-normal text-fg-dim">{hint}</span>}
      </h2>
      {right}
    </div>
  );
}

export function CtaPanel({
  eyebrow,
  title,
  body,
  children,
}: {
  eyebrow?: string;
  title: string;
  body?: string;
  children: React.ReactNode;
}) {
  return (
    <section
      className="text-center px-6 py-12 rounded-2xl border border-border my-4"
      style={{ background: "linear-gradient(135deg, var(--accent-soft), transparent)" }}
    >
      {eyebrow && <span className="eyebrow">{eyebrow}</span>}
      <h2 className="text-2xl font-semibold mb-3 text-fg">{title}</h2>
      {body && <p className="max-w-lg mx-auto mb-5 text-fg-muted">{body}</p>}
      <div className="flex gap-3 justify-center flex-wrap">{children}</div>
    </section>
  );
}

export function PageHeader({
  eyebrow,
  title,
  body,
  align = "left",
}: {
  eyebrow?: string;
  title: string;
  body?: React.ReactNode;
  align?: "left" | "center";
}) {
  const wrap = align === "center" ? "max-w-[820px] mx-auto text-center" : "max-w-[820px]";
  return (
    <div className={`${wrap} mb-8`}>
      {eyebrow && <span className="eyebrow">{eyebrow}</span>}
      <h1 className="text-3xl md:text-4xl font-semibold tracking-tight mb-3 text-fg">{title}</h1>
      {body && <p className="text-base text-fg-muted">{body}</p>}
    </div>
  );
}
