import type { ReactNode } from "react";

type FilterFieldProps = {
  label: string;
  children: ReactNode;
  className?: string;
};

export function FilterField({ label, children, className }: FilterFieldProps) {
  return (
    <label className={["filter-field", className].filter(Boolean).join(" ")}>
      <span className="filter-field-label">{label}</span>
      {children}
    </label>
  );
}
