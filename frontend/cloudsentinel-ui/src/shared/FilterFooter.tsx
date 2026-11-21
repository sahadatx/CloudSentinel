type FilterFooterProps = {
  active: boolean;
  onReset: () => void;
  className?: string;
};

export function FilterFooter({
  active,
  onReset,
  className,
}: FilterFooterProps) {
  return (
    <div
      className={["filter-footer", "shared-filter-footer", className]
        .filter(Boolean)
        .join(" ")}
    >
      <span className="filter-hint">
        Results update automatically when filters change.
      </span>
      <button
        type="button"
        className="text-button filter-reset-button"
        disabled={!active}
        onClick={onReset}
      >
        Reset filters
      </button>
    </div>
  );
}
