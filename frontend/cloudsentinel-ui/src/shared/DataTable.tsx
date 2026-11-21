import type { ComponentPropsWithoutRef } from "react";

type DataTableProps = ComponentPropsWithoutRef<"table"> & {
  caption: string;
  actions?: boolean;
};

export function DataTable({
  caption,
  actions = false,
  className,
  children,
  ...props
}: DataTableProps) {
  return (
    <div
      className="data-table-scroll"
      role="region"
      aria-label={caption}
      tabIndex={0}
    >
      <table
        {...props}
        className={["data-table", actions && "has-actions", className]
          .filter(Boolean)
          .join(" ")}
      >
        <caption className="table-caption">{caption}</caption>
        {children}
      </table>
    </div>
  );
}
