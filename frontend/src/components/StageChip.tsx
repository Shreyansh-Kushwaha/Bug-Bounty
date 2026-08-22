export default function StageChip({ stage }: { stage: string }) {
  return (
    <span className="stage-chip" data-stage={stage}>
      {stage}
    </span>
  );
}

export function SevChip({ severity }: { severity?: string | null }) {
  if (!severity) return <span style={{ color: "var(--fg-dim)" }}>—</span>;
  return (
    <span className="sev-chip" data-sev={severity.toLowerCase()}>
      {severity}
    </span>
  );
}
