export function RiskProgress({
  value,
  label,
}: {
  value: number;
  label: string;
}) {
  const score = Number.isFinite(value) ? Math.min(100, Math.max(0, value)) : 0;
  const tone =
    score >= 80
      ? "critical"
      : score >= 60
        ? "high"
        : score >= 40
          ? "medium"
          : score >= 20
            ? "low"
            : "info";
  return (
    <progress
      className={`risk-progress risk-progress-${tone}`}
      max="100"
      value={score}
      aria-label={label}
    />
  );
}
