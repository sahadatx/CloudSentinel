import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api, ApiError } from "../shared/api";
import { useAuth } from "../shared/useAuth";
import { AuthBrand } from "../components/AuthBrand";
import { Icon } from "../shared/Icon";

type ResetState = "loading" | "valid" | "invalid" | "unavailable" | "success";

export function InvitationAcceptancePage() {
  const [searchParams] = useSearchParams();
  const [token] = useState(
    () =>
      new URLSearchParams(window.location.hash.slice(1)).get("token") ??
      searchParams.get("token") ??
      "",
  );
  const [busy, setBusy] = useState(false);
  const [accepted, setAccepted] = useState(false);
  const [error, setError] = useState("");
  const [minimumLength, setMinimumLength] = useState(12);
  const [validating, setValidating] = useState(Boolean(token));
  const [validInvitation, setValidInvitation] = useState(Boolean(token));

  useEffect(() => {
    if (token) window.history.replaceState(window.history.state, "", "/accept-invitation");
    if (!token) return;
    let active = true;
    api.validateInvitation(token).then(({ minimum_length }) => {
      if (!active) return;
      setMinimumLength(minimum_length);
      setValidInvitation(true);
      setValidating(false);
    }).catch(() => {
      if (!active) return;
      setValidInvitation(false);
      setValidating(false);
    });
    return () => { active = false; };
  }, [token]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || !token || !validInvitation) return;
    const form = new FormData(event.currentTarget);
    const password = String(form.get("password"));
    if (password !== String(form.get("confirm_password"))) {
      setError("Passwords do not match.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      await api.acceptInvitation(token, password);
      setAccepted(true);
    } catch (reason) {
      if (reason instanceof ApiError && (reason.status === 400 || reason.status === 409 || reason.status === 422)) {
        setError("This invitation is invalid, expired, or already used. Ask your organization administrator for a new invitation.");
      } else {
        setError("We couldn't accept this invitation. Please try again.");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login-page login-recovery-page">
      <section className="recovery-content">
        <Link className="login-brand recovery-brand" to="/login" aria-label="CloudSentinel sign in">
          <AuthBrand />
        </Link>
        <div className="login-panel recovery-panel" aria-live="polite">
          {accepted ? (
            <div className="recovery-success">
              <span className="recovery-icon" aria-hidden="true"><Icon name="check" /></span>
              <h2>Account created</h2>
              <p className="login-subtitle">Your invitation was accepted. Sign in with your work email and the password you created.</p>
              <Link className="login-submit recovery-link" to="/login">Continue to sign in</Link>
            </div>
          ) : !token || !validInvitation ? (
            <div className="recovery-success">
              <span className="recovery-icon recovery-invalid" aria-hidden="true"><Icon name="warning" /></span>
              <h2>Invitation link unavailable</h2>
              <p className="login-subtitle">This link is missing its invitation token. Ask your organization administrator to send a new invitation.</p>
              <Link className="recovery-back" to="/login">← Back to sign in</Link>
            </div>
          ) : validating ? (
            <p className="login-subtitle">Validating your invitation…</p>
          ) : (
            <>
              <span className="recovery-icon" aria-hidden="true"><Icon name="mail" /></span>
              <h2>Accept your invitation</h2>
              <p className="login-subtitle">Create a secure password to join your CloudSentinel organization.</p>
              <form className="recovery-form" onSubmit={submit} aria-busy={busy}>
                <PasswordInput id="invite-password" name="password" label="Create password" disabled={busy} autoComplete="new-password" minLength={minimumLength} />
                <small className="login-field-hint">Use at least {minimumLength} characters.</small>
                <PasswordInput id="invite-confirm-password" name="confirm_password" label="Confirm password" disabled={busy} autoComplete="new-password" minLength={minimumLength} />
                {error && <div className="login-error" role="alert">{error}</div>}
                <button className="login-submit" type="submit" disabled={busy}>{busy ? "Accepting invitation…" : <>Accept invitation <Icon name="arrow-right" /></>}</button>
              </form>
              <Link className="recovery-back" to="/login">← Back to sign in</Link>
            </>
          )}
        </div>
        <p className="recovery-security"><Icon name="lock" /> Secure organization access</p>
        <p className="recovery-copyright">© 2026 CloudSentinel</p>
      </section>
    </main>
  );
}

function formError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 401) return "Your session has expired. Sign in again.";
    if (error.status === 422) return "Password must contain at least 12 characters.";
    if (error.status >= 500) return "We couldn't update your password. Please try again.";
  }
  return "Unable to reach CloudSentinel. Check your connection and try again.";
}

function PasswordInput({
  id,
  name,
  label,
  disabled,
  autoComplete,
  minLength = 12,
}: {
  id: string;
  name: string;
  label: string;
  disabled: boolean;
  autoComplete: string;
  minLength?: number;
}) {
  const [visible, setVisible] = useState(false);
  return (
    <>
      <label htmlFor={id}>{label}</label>
      <div className="login-input-wrap">
        <span aria-hidden="true"><Icon name="lock" /></span>
        <input
          id={id}
          name={name}
          type={visible ? "text" : "password"}
          autoComplete={autoComplete}
          minLength={minLength}
          maxLength={128}
          required
          disabled={disabled}
        />
        <button
          type="button"
          className="password-toggle"
          aria-label={visible ? `Hide ${label.toLowerCase()}` : `Show ${label.toLowerCase()}`}
          aria-pressed={visible}
          aria-controls={id}
          onClick={() => setVisible((value) => !value)}
          disabled={disabled}
        >
          <Icon name={visible ? "eye-off" : "eye"} />
        </button>
      </div>
    </>
  );
}

export function ResetPasswordPage() {
  const { token: routeToken = "" } = useParams();
  const [token] = useState(
    () => new URLSearchParams(window.location.hash.slice(1)).get("token") ?? routeToken,
  );
  const navigate = useNavigate();
  const { clearLocalSession } = useAuth();
  const [state, setState] = useState<ResetState>(token ? "loading" : "invalid");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [minimumLength, setMinimumLength] = useState(12);

  useEffect(() => {
    // Remove the bearer-like token from browser history as soon as it is read.
    window.history.replaceState(window.history.state, "", "/reset-password");
    if (!token) return;
    let active = true;
    api
      .validatePasswordReset(token)
      .then(({ valid, minimum_length }) => {
        if (!active) return;
        setMinimumLength(minimum_length);
        setState(valid ? "valid" : "invalid");
      })
      .catch((reason: unknown) => {
        if (!active) return;
        if (reason instanceof ApiError && reason.status === 400) {
          setState("invalid");
        } else {
          setError(formError(reason));
          setState("unavailable");
        }
      });
    return () => {
      active = false;
    };
  }, [token]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || state !== "valid") return;
    setError("");
    const form = new FormData(event.currentTarget);
    const password = String(form.get("new_password"));
    if (password !== String(form.get("confirm_password"))) {
      setError("Passwords do not match.");
      return;
    }
    setBusy(true);
    try {
      await api.resetPassword(token, password);
      clearLocalSession();
      setState("success");
    } catch (reason) {
      if (reason instanceof ApiError && (reason.status === 400 || reason.status === 422)) {
        setState("invalid");
        setError("Reset link is invalid or expired. Request a new link to continue.");
      } else {
        setError(formError(reason));
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login-page login-recovery-page">
      <section className="recovery-content">
        <Link className="login-brand recovery-brand" to="/login" aria-label="CloudSentinel sign in">
          <AuthBrand />
        </Link>
        <div className="login-panel recovery-panel" aria-live="polite">
          {state === "loading" && <p className="login-subtitle">Validating your secure reset link…</p>}
          {(state === "invalid" || state === "unavailable") && (
            <div className="recovery-success">
              <span className="recovery-icon recovery-invalid" aria-hidden="true"><Icon name="warning" /></span>
              <h2>{state === "invalid" ? "Reset link unavailable" : "Unable to validate link"}</h2>
              <p className="login-subtitle">{state === "invalid" ? "This password reset link is invalid or has expired. Request a new link to continue." : "We couldn't validate this reset link. Check your connection or request a new link."}</p>
              {error && <div className="login-error" role="alert">{error}</div>}
              <Link className="login-submit recovery-link" to="/forgot-password">Request a new reset link</Link>
              <Link className="recovery-back" to="/login">← Back to sign in</Link>
            </div>
          )}
          {state === "valid" && (
            <>
              <span className="recovery-icon" aria-hidden="true"><Icon name="lock" /></span>
              <h2>Set a new password</h2>
              <p className="login-subtitle">Choose a new password for your CloudSentinel account.</p>
              <form className="recovery-form" onSubmit={submit} aria-busy={busy}>
                <PasswordInput id="reset-new-password" name="new_password" label="New password" disabled={busy} autoComplete="new-password" minLength={minimumLength} />
                <small className="login-field-hint">Use at least {minimumLength} characters.</small>
                <PasswordInput id="reset-confirm-password" name="confirm_password" label="Confirm password" disabled={busy} autoComplete="new-password" minLength={minimumLength} />
                {error && <div className="login-error" role="alert">{error}</div>}
                <button className="login-submit" type="submit" disabled={busy}>{busy ? "Updating password…" : <>Update password <Icon name="arrow-right" /></>}</button>
              </form>
              <Link className="recovery-back" to="/login">← Back to sign in</Link>
            </>
          )}
          {state === "success" && (
            <div className="recovery-success">
              <span className="recovery-icon" aria-hidden="true"><Icon name="check" /></span>
              <h2>Password updated</h2>
              <p className="login-subtitle">Your password has been changed. Sign in with your new password.</p>
              <button className="login-submit" type="button" onClick={() => navigate("/login", { replace: true })}>Continue to sign in</button>
            </div>
          )}
        </div>
        <p className="recovery-security"><Icon name="lock" /> Secure password recovery</p>
        <p className="recovery-copyright">© 2026 CloudSentinel</p>
      </section>
    </main>
  );
}

export function ForcePasswordChangePage() {
  const { changePassword } = useAuth();
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [minimumLength, setMinimumLength] = useState(12);

  useEffect(() => {
    let active = true;
    api.getPasswordPolicy().then(({ minimum_length }) => {
      if (active) setMinimumLength(minimum_length);
    }).catch(() => {
      if (active) setError("Unable to load your organization's password requirements.");
    });
    return () => { active = false; };
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    setError("");
    const form = new FormData(event.currentTarget);
    const currentPassword = String(form.get("current_password"));
    const newPassword = String(form.get("new_password"));
    if (newPassword !== String(form.get("confirm_password"))) {
      setError("Passwords do not match.");
      return;
    }
    if (newPassword === currentPassword) {
      setError("Choose a password different from your current password.");
      return;
    }
    setBusy(true);
    try {
      await changePassword(currentPassword, newPassword);
      navigate("/", { replace: true });
    } catch (reason) {
      if (reason instanceof ApiError && reason.status === 401) {
        setError("Your session or current password is no longer valid. Sign in again.");
      } else {
        setError(formError(reason));
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login-page login-recovery-page">
      <section className="recovery-content">
        <div className="login-brand recovery-brand">
          <AuthBrand />
        </div>
        <div className="login-panel recovery-panel">
          <span className="recovery-icon" aria-hidden="true"><Icon name="lock" /></span>
          <h2>Update your password</h2>
          <p className="login-subtitle">For security reasons, change your password before continuing.</p>
          <form className="recovery-form" onSubmit={submit} aria-busy={busy}>
            <PasswordInput id="force-current-password" name="current_password" label="Current password" disabled={busy} autoComplete="current-password" minLength={1} />
            <PasswordInput id="force-new-password" name="new_password" label="New password" disabled={busy} autoComplete="new-password" minLength={minimumLength} />
            <small className="login-field-hint">Use at least {minimumLength} characters.</small>
            <PasswordInput id="force-confirm-password" name="confirm_password" label="Confirm new password" disabled={busy} autoComplete="new-password" minLength={minimumLength} />
            {error && <div className="login-error" role="alert">{error}</div>}
            <button className="login-submit" type="submit" disabled={busy}>{busy ? "Updating password…" : <>Update password <Icon name="arrow-right" /></>}</button>
          </form>
          <p className="forced-password-notice"><Icon name="lock" /> Password change required to access CloudSentinel.</p>
        </div>
        <p className="recovery-copyright">© 2026 CloudSentinel</p>
      </section>
    </main>
  );
}
