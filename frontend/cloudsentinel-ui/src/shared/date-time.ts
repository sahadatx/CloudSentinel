function organizationTimeZone(): string {
  const timeZone = document.documentElement.dataset.timezone ?? "UTC";
  try {
    new Intl.DateTimeFormat("en-US", { timeZone }).format(0);
    return timeZone;
  } catch {
    return "UTC";
  }
}

function organizationDateTimeFormat(): string {
  return document.documentElement.dataset.dateTimeFormat ?? "YYYY-MM-DD HH:mm";
}

function formatParts(date: Date, hourCycle: "h12" | "h23") {
  return new Intl.DateTimeFormat("en-US", {
    timeZone: organizationTimeZone(),
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle,
  }).formatToParts(date);
}

export function formatOrganizationDateTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return "—";

  const format = organizationDateTimeFormat();
  const parts = formatParts(
    date,
    format === "MM/DD/YYYY hh:mm A" ? "h12" : "h23",
  );
  const part = (type: Intl.DateTimeFormatPartTypes) =>
    parts.find((item) => item.type === type)?.value ?? "";
  const year = part("year");
  const month = part("month");
  const day = part("day");
  const hour = part("hour");
  const minute = part("minute");

  if (format === "MM/DD/YYYY hh:mm A")
    return `${month}/${day}/${year} ${hour}:${minute} ${part("dayPeriod")}`;
  if (format === "DD/MM/YYYY HH:mm")
    return `${day}/${month}/${year} ${hour}:${minute}`;
  return `${year}-${month}-${day} ${hour}:${minute}`;
}

export function organizationDateToUtcIso(
  value: string,
  edge: "start" | "end",
): string | null {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!match) return null;

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const startOfDay = Date.UTC(year, month - 1, day);
  const selected = new Date(startOfDay);
  if (
    selected.getUTCFullYear() !== year ||
    selected.getUTCMonth() !== month - 1 ||
    selected.getUTCDate() !== day
  ) {
    return null;
  }

  const targetWallTime = startOfDay + (edge === "end" ? 86_400_000 : 0);
  const formatter = new Intl.DateTimeFormat("en-US", {
    timeZone: organizationTimeZone(),
    calendar: "gregory",
    numberingSystem: "latn",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  });
  const offsetAt = (instant: number) => {
    const parts = formatter.formatToParts(new Date(instant));
    const part = (type: Intl.DateTimeFormatPartTypes) =>
      Number(parts.find((item) => item.type === type)?.value ?? 0);
    const wallTime = Date.UTC(
      part("year"),
      part("month") - 1,
      part("day"),
      part("hour"),
      part("minute"),
      part("second"),
    );
    return wallTime - Math.floor(instant / 1000) * 1000;
  };

  let utcInstant = targetWallTime;
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const next = targetWallTime - offsetAt(utcInstant);
    if (next === utcInstant) break;
    utcInstant = next;
  }

  if (edge === "end") utcInstant -= 1;
  const iso = new Date(utcInstant).toISOString();
  return edge === "end" ? iso.replace(".999Z", ".999999Z") : iso;
}
