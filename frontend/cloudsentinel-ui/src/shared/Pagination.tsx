import { useEffect } from "react";

type PaginationProps = {
  total: number;
  offset: number;
  limit: number;
  onOffsetChange: (offset: number) => void;
  disabled?: boolean;
  label: string;
};

export function Pagination({
  total,
  offset,
  limit,
  onOffsetChange,
  disabled = false,
  label,
}: PaginationProps) {
  const itemCount = Number.isFinite(total) ? Math.max(0, Math.floor(total)) : 0;
  const pageSize = Number.isFinite(limit) ? Math.max(1, Math.floor(limit)) : 1;
  const pageCount = Math.max(1, Math.ceil(itemCount / pageSize));
  const requestedPage = Number.isFinite(offset)
    ? Math.floor(Math.max(0, offset) / pageSize)
    : 0;
  const pageIndex = Math.min(pageCount - 1, requestedPage);
  const currentOffset = pageIndex * pageSize;
  const page = pageIndex + 1;
  const start = itemCount ? currentOffset + 1 : 0;
  const end = Math.min(currentOffset + pageSize, itemCount);
  const formatNumber = (value: number) => value.toLocaleString();

  useEffect(() => {
    if (!disabled && offset !== currentOffset) onOffsetChange(currentOffset);
  }, [currentOffset, disabled, offset, onOffsetChange]);

  return (
    <nav
      className="cloud-accounts-pagination"
      aria-label={label}
      aria-busy={disabled}
    >
      <div
        className="cloud-accounts-pagination-summary"
        aria-live="polite"
        aria-atomic="true"
      >
        <strong>
          {formatNumber(start)}–{formatNumber(end)}
        </strong>
        <span>/ Total {formatNumber(itemCount)}</span>
      </div>
      <div className="cloud-accounts-pagination-controls">
        <span className="cloud-accounts-page-indicator">
          Page <strong>{formatNumber(page)}</strong> of{" "}
          <strong>{formatNumber(pageCount)}</strong>
        </span>
        <button
          type="button"
          className="cloud-accounts-page-button"
          aria-label="Previous page"
          disabled={disabled || page <= 1}
          onClick={() => onOffsetChange(Math.max(0, currentOffset - pageSize))}
        >
          <svg
            className="cloud-accounts-page-icon"
            viewBox="0 0 16 16"
            aria-hidden="true"
            focusable="false"
          >
            <path d="m10 3-5 5 5 5" />
          </svg>
          Previous
        </button>
        <button
          type="button"
          className="cloud-accounts-page-button"
          aria-label="Next page"
          disabled={disabled || page >= pageCount}
          onClick={() =>
            onOffsetChange(
              Math.min((pageCount - 1) * pageSize, currentOffset + pageSize),
            )
          }
        >
          Next
          <svg
            className="cloud-accounts-page-icon"
            viewBox="0 0 16 16"
            aria-hidden="true"
            focusable="false"
          >
            <path d="m6 3 5 5-5 5" />
          </svg>
        </button>
      </div>
    </nav>
  );
}
