import type { ReactNode } from "react";
import { kpiIcon } from "./kpi-utils";
import { Icon } from "./Icon";

export function KpiIcon({ label }: { label: string }): ReactNode {
  return (
    <span className="kpi-icon" aria-hidden="true">
      <Icon name={kpiIcon(label)} />
    </span>
  );
}
