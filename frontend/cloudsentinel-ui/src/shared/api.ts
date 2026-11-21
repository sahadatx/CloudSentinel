export type User = {
  id: string;
  email: string;
  display_name: string;
  organization_id: string;
  membership_id: string;
  role: string;
  permissions: string[];
  force_password_change: boolean;
};

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export type Page<T> = {
  items: T[];
  total: number;
  offset: number;
  limit: number;
};
export type Account = {
  id: string;
  name: string;
  account_id: string;
  primary_region: string | null;
  role_arn: string | null;
  environment: string | null;
  connection_status: string;
  validation_mode: "real" | "mock" | null;
  last_validated_at: string | null;
  last_error_code: string | null;
  last_scan_at: string | null;
  created_at: string;
  regions: { region_code: string; is_enabled: boolean }[];
};
export type Asset = {
  id: string;
  provider: string;
  cloud_account_id: string;
  last_scan_job_id: string | null;
  cloud_account_name: string | null;
  environment: string | null;
  resource_type: string;
  resource_id: string;
  resource_arn: string | null;
  region_code: string;
  name: string | null;
  tags: Record<string, string>;
  owner_metadata: Record<string, string> | null;
  attributes: Record<string, unknown>;
  status: "active" | "stale" | "removed";
  missed_scan_count: number;
  risk_score: number | null;
  compliance_status:
    | "PASS"
    | "FAIL"
    | "PARTIAL"
    | "NOT_ASSESSED"
    | "NOT_APPLICABLE"
    | null;
  compliance_last_assessed_at: string | null;
  assignee_name: string | null;
  first_seen_at: string;
  last_seen_at: string;
  updated_at?: string;
};
export type Finding = {
  id: string;
  cloud_account_id: string;
  asset_id: string;
  asset_name: string | null;
  asset_type: string | null;
  account_name: string | null;
  data_origin: "local_mock" | null;
  rule_id: string;
  rule_version: string;
  title: string;
  description: string;
  remediation: string;
  severity: string;
  status: string;
  category: string;
  region_code: string;
  last_seen_at: string;
  first_seen_at: string;
  due_at: string | null;
  risk_score: number | null;
  assigned_to_user_id: string | null;
  assignee_name?: string | null;
  assignee_role?: string | null;
};
export type Policy = {
  id: string;
  rule_id: string;
  name: string;
  description: string;
  provider: string;
  resource_types: string[];
  category: string;
  severity: string;
  status: "enabled" | "disabled";
  version: number;
  detection_logic: Record<string, unknown>;
  evidence_logic: Record<string, unknown>;
  remediation: string;
  compliance_controls: { framework: string; control: string; title: string }[];
  is_builtin: boolean;
  created_at: string;
  updated_at: string;
};
export type Notification = {
  id: string;
  category: string;
  title: string;
  message: string;
  resource_type: string | null;
  resource_id: string | null;
  read_at: string | null;
  created_at: string;
};
export type OrganizationSecuritySettings = {
  password_min_length: number;
  session_ttl_days: number;
  remembered_session_ttl_days: number;
  max_concurrent_sessions: number;
};
export type OrganizationRetentionSettings = { audit_retention_days: number };
export type SamlIdentitySettings = {
  configured: boolean;
  active: boolean;
  enforce_sso: boolean;
  jit_provisioning: boolean;
  require_mfa: boolean;
  default_role_code: string;
  email_attribute: string;
  name_attribute: string;
  mfa_contexts: string[];
  metadata_url: string;
  login_url: string;
};

let accessToken: string | null = null;
type RefreshResponse = {
  access_token: string;
  user: User;
  remember_session: boolean;
};
let refreshInFlight: Promise<RefreshResponse | null> | null = null;

export function setAccessToken(token: string | null) {
  accessToken = token;
}

function csrfToken(): string | undefined {
  return document.cookie
    .split("; ")
    .find((item) => item.startsWith("cloudsentinel_csrf="))
    ?.split("=")
    .slice(1)
    .join("=");
}

async function rawRequest<T>(
  path: string,
  init: RequestInit = {},
  canRefresh = true,
  responseAsBlob = false,
): Promise<T> {
  const headers = new Headers(init.headers);
  if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
  if (init.body && !(init.body instanceof FormData) && !headers.has("Content-Type"))
    headers.set("Content-Type", "application/json");
  const response = await fetch(path, {
    ...init,
    headers,
    credentials: "include",
  });
  if (
    response.status === 401 &&
    canRefresh &&
    path !== "/auth/login" &&
    path !== "/auth/refresh"
  ) {
    const csrf = csrfToken();
    if (csrf) {
      const refreshed = await fetch("/auth/refresh", {
        method: "POST",
        credentials: "include",
        headers: { "X-CSRF-Token": decodeURIComponent(csrf) },
      });
      if (refreshed.ok) {
        const token = (await refreshed.json()) as { access_token: string };
        setAccessToken(token.access_token);
        return rawRequest<T>(path, init, false, responseAsBlob);
      }
    }
  }
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const payload = (await response.json()) as {
        error?: { message?: string };
        detail?: string;
      };
      message = payload.error?.message ?? payload.detail ?? message;
    } catch {
      // A safe generic message is retained for non-JSON infrastructure responses.
    }
    throw new ApiError(message, response.status);
  }
  if (response.status === 204) return undefined as T;
  if (responseAsBlob) return (await response.blob()) as T;
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json"))
    return (await response.json()) as T;
  return (await response.blob()) as T;
}

export const api = {
  get: <T>(path: string) => rawRequest<T>(path),
  post: <T>(path: string, body?: unknown) =>
    rawRequest<T>(path, {
      method: "POST",
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
  upload: <T>(path: string, body: FormData) =>
    rawRequest<T>(path, { method: "POST", body }),
  patch: <T>(path: string, body: unknown) =>
    rawRequest<T>(path, { method: "PATCH", body: JSON.stringify(body) }),
  put: <T>(path: string, body?: unknown) =>
    rawRequest<T>(path, {
      method: "PUT",
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
  delete: <T>(path: string) => rawRequest<T>(path, { method: "DELETE" }),
  login: (
    email: string,
    password: string,
    mfaCode?: string,
  ) =>
    rawRequest<
      | { access_token: string; user: User; remember_session: boolean }
      | { mfa_required: true }
    >(
      "/auth/login",
      {
        method: "POST",
        body: JSON.stringify({ email, password, ...(mfaCode ? { mfa_code: mfaCode } : {}) }),
      },
      false,
    ),
  exchangeSsoCode: (code: string) =>
    rawRequest<{ access_token: string; user: User; remember_session: boolean }>(
      "/auth/sso/exchange",
      { method: "POST", body: JSON.stringify({ code }) },
      false,
    ),
  forgotPassword: (email: string) =>
    rawRequest<{ message: string }>(
      "/auth/forgot-password",
      { method: "POST", body: JSON.stringify({ email }) },
      false,
    ),
  validatePasswordReset: (token: string) =>
    rawRequest<{ valid: boolean; minimum_length: number }>(
      "/auth/password-reset/validate",
      { method: "POST", body: JSON.stringify({ token }) },
      false,
    ),
  resetPassword: (token: string, new_password: string) =>
    rawRequest<{ status: string }>(
      "/auth/password-reset",
      { method: "POST", body: JSON.stringify({ token, new_password }) },
      false,
    ),
  acceptInvitation: (token: string, password: string) =>
    rawRequest<{ status: string }>(
      "/auth/accept-invitation",
      { method: "POST", body: JSON.stringify({ token, password }) },
      false,
    ),
  validateInvitation: (token: string) =>
    rawRequest<{ valid: boolean; minimum_length: number }>(
      "/auth/invitation/validate",
      { method: "POST", body: JSON.stringify({ token }) },
      false,
    ),
  changePassword: (current_password: string, new_password: string) =>
    rawRequest<{ force_password_change: boolean }>("/auth/change-password", {
      method: "POST",
      body: JSON.stringify({ current_password, new_password }),
    }, false),
  getPasswordPolicy: () => rawRequest<{ minimum_length: number }>("/auth/password-policy"),
  logout: () => {
    const csrf = csrfToken();
    return rawRequest<void>(
      "/auth/logout",
      {
        method: "POST",
        headers: csrf ? { "X-CSRF-Token": decodeURIComponent(csrf) } : {},
      },
      false,
    );
  },
  refresh: () => {
    if (refreshInFlight) return refreshInFlight;
    const csrf = csrfToken();
    if (!csrf) return Promise.resolve(null);
    const request = rawRequest<RefreshResponse>(
      "/auth/refresh",
      { method: "POST", headers: { "X-CSRF-Token": decodeURIComponent(csrf) } },
      false,
    );
    refreshInFlight = request.finally(() => {
      refreshInFlight = null;
    });
    return refreshInFlight;
  },
  exportReport: async (id: string, format: "json" | "csv" | "pdf") => {
    const blob = await rawRequest<Blob>(
      `/reports/${id}/export?format=${format}`,
      {},
      true,
      true,
    );
    const href = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = href;
    link.download = `cloudsentinel-report-${id}.${format}`;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(href);
  },
};
