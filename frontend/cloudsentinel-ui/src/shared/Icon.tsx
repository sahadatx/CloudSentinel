import type { ReactNode } from "react";
import type { IconName } from "./kpi-utils";

const paths: Record<IconName, ReactNode> = {
  mail: (
    <>
      <rect x="3" y="5" width="18" height="14" rx="2" />
      <path d="m3 6 9 7 9-7" />
    </>
  ),
  eye: (
    <>
      <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z" />
      <circle cx="12" cy="12" r="3" />
    </>
  ),
  "eye-off": (
    <path d="m3 3 18 18M10.6 5.1A13 13 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3 3.9M6.2 6.2A18 18 0 0 0 2 12s3.5 7 10 7a13 13 0 0 0 5.8-1.5M9.9 9.9a3 3 0 0 0 4.2 4.2" />
  ),
  refresh: (
    <path d="M3 10a9 9 0 0 1 15-6l3 3m0-4v5h-5M21 14a9 9 0 0 1-15 6l-3-3m0 4v-5h5" />
  ),
  search: (
    <>
      <circle cx="10.5" cy="10.5" r="7" />
      <path d="m16 16 5 5" />
    </>
  ),
  "arrow-right": <path d="M4 12h16m-6-6 6 6-6 6" />,
  "arrow-left": <path d="M20 12H4m6-6-6 6 6 6" />,
  "chevron-down": <path d="m6 9 6 6 6-6" />,
  logout: <path d="M9 3H4v18h5m0-9h12m-5-5 5 5-5 5" />,
  menu: <path d="M3 6h18M3 12h18M3 18h18" />,
  close: <path d="m6 6 12 12M6 18 18 6" />,
  shield: (
    <>
      <path d="m12 3 8 3v5c0 5-3.5 8-8 10-4.5-2-8-5-8-10V6l8-3Z" />
      <path d="m8.5 12 2.3 2.3 4.7-4.8" />
    </>
  ),
  dashboard: (
    <>
      <rect x="3" y="3" width="7" height="7" rx="1.5" />
      <rect x="14" y="3" width="7" height="7" rx="1.5" />
      <rect x="3" y="14" width="7" height="7" rx="1.5" />
      <rect x="14" y="14" width="7" height="7" rx="1.5" />
    </>
  ),
  cloud: (
    <path d="M6.5 18a4.5 4.5 0 0 1-.6-9 6.5 6.5 0 0 1 12.5-1A5 5 0 0 1 18 18H6.5Z" />
  ),
  assets: (
    <>
      <path d="m12 3 9 5-9 5-9-5 9-5Zm-9 9 9 5 9-5M3 16l9 5 9-5" />
    </>
  ),
  warning: (
    <>
      <path d="m10.3 4.5-8 14A1.7 1.7 0 0 0 3.8 21h16.4a1.7 1.7 0 0 0 1.5-2.5l-8-14a2 2 0 0 0-3.4 0Z" />
      <path d="M12 9v5m0 3v.1" />
    </>
  ),
  check: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="m8 12 2.5 2.5 5.5-5.5" />
    </>
  ),
  bell: (
    <>
      <path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9Zm-8 12a2 2 0 0 0 4 0" />
    </>
  ),
  scan: (
    <>
      <path d="M8 3H4a1 1 0 0 0-1 1v4m13-5h4a1 1 0 0 1 1 1v4M3 16v4a1 1 0 0 0 1 1h4m13-5v4a1 1 0 0 1-1 1h-4M3 12h18" />
      <circle cx="12" cy="12" r="4" />
    </>
  ),
  user: (
    <>
      <circle cx="12" cy="8" r="4" />
      <path d="M4 21v-2a8 8 0 0 1 16 0v2" />
    </>
  ),
  team: (
    <>
      <circle cx="9" cy="8" r="3" />
      <path d="M2 21v-2a7 7 0 0 1 14 0v2M17 4a3 3 0 0 1 0 6m2 11v-2a6 6 0 0 0-2-4.5" />
    </>
  ),
  report: (
    <>
      <path d="M14 3H5v18h14V8l-5-5Z" />
      <path d="M14 3v5h5M8 12h8m-8 4h6" />
    </>
  ),
  activity: (
    <>
      <path d="M8 6h13M8 12h13M8 18h13M3 6h.1M3 12h.1M3 18h.1" />
    </>
  ),
  policy: (
    <>
      <path d="M4 6h16M4 12h16M4 18h16" />
      <circle cx="8" cy="6" r="2" />
      <circle cx="16" cy="12" r="2" />
      <circle cx="10" cy="18" r="2" />
    </>
  ),
  lock: (
    <>
      <rect x="5" y="10" width="14" height="11" rx="2" />
      <path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2" />
    </>
  ),
  risk: (
    <>
      <path d="M3 3v18h18M6 16l5-6 4 3 6-8m-5 0h5v5" />
    </>
  ),
  remediation: (
    <>
      <path d="m14 6 4 4M3 21l5-1 12-12a2.8 2.8 0 0 0-4-4L4 16l-1 5Z" />
    </>
  ),
  organization: (
    <>
      <path d="M4 21V3h12v18M16 9h4v12M2 21h20M8 7h4m-4 4h4m-4 4h4m-2 3v3" />
    </>
  ),
  settings: (
    <>
      <path d="m9 3-.7 2.2-2 .9-2.1-.5-2 3.4 1.5 1.7v2.6L2.2 15l2 3.4 2.1-.5 2 .9L9 21h4l.7-2.2 2-.9 2.1.5 2-3.4-1.5-1.7v-2.6L19.8 9l-2-3.4-2.1.5-2-.9L13 3H9Z" />
      <circle cx="11" cy="12" r="3" />
    </>
  ),
};

export function Icon({
  name,
  className,
}: {
  name: IconName;
  className?: string;
}) {
  return (
    <svg
      className={className}
      width="20"
      height="20"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {paths[name]}
    </svg>
  );
}
