export type IconName =
  | "shield"
  | "dashboard"
  | "cloud"
  | "assets"
  | "warning"
  | "check"
  | "bell"
  | "scan"
  | "user"
  | "team"
  | "report"
  | "activity"
  | "policy"
  | "lock"
  | "risk"
  | "remediation"
  | "organization"
  | "settings"
  | "mail"
  | "eye"
  | "eye-off"
  | "refresh"
  | "search"
  | "arrow-right"
  | "arrow-left"
  | "chevron-down"
  | "logout"
  | "menu"
  | "close";

const iconRules: Array<[RegExp, IconName]> = [
  [/security score|risk score|overall risk/i, "shield"],
  [/dashboard/i, "dashboard"],
  [/cloud account|account/i, "cloud"],
  [/asset|resource/i, "assets"],
  [
    /critical|failed|error|^high$|^medium$|^low$|overdue|suppressed/i,
    "warning",
  ],
  [/finding|issue|^open$|informational/i, "shield"],
  [
    /compliance|passed|completed|verified|^connected$|^active$|^enabled$|^generated$|resolved|closed/i,
    "check",
  ],
  [/alert|notification/i, "bell"],
  [/scan|running|queued|pending/i, "scan"],
  [/user|member|invitation/i, "user"],
  [/team/i, "team"],
  [/report|export/i, "report"],
  [/event|action|activity|audit/i, "activity"],
  [/polic|control/i, "policy"],
  [/disabled|locked/i, "lock"],
  [/risk/i, "risk"],
  [/remediation/i, "remediation"],
  [/organization/i, "organization"],
  [/settings/i, "settings"],
];

const toneRules: Array<[RegExp, string]> = [
  [/\b(critical|failed|errors?|locked|overdue|non[ -]?compliant)\b/i, "error"],
  [/\bhigh[ -]?risk\b|^high$/i, "high"],
  [/\b(pending|queued|verification)\b|^medium$/i, "pending"],
  [
    /\b(disabled|inactive|disconnected|archived|resolved|closed|informational)\b/i,
    "muted",
  ],
  [
    /\b(connected|active|enabled|passed|completed|compliant|generated)\b|^low$/i,
    "connected",
  ],
];

export function kpiIcon(label: string): IconName {
  return iconRules.find(([pattern]) => pattern.test(label))?.[1] ?? "report";
}

export function kpiTone(label: string): string {
  return toneRules.find(([pattern]) => pattern.test(label))?.[1] ?? "blue";
}
