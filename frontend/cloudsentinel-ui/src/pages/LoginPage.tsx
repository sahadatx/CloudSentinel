import { useState } from "react";
import type { FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, ApiError } from "../shared/api";
import { useAuth } from "../shared/useAuth";
import { AuthBrand } from "../components/AuthBrand";
import { Icon } from "../shared/Icon";

function loginError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 401) return "Invalid email or password.";
    if (error.status === 429) return "Too many attempts. Wait a moment and try again.";
    if (error.status === 422) return "Check your email and password.";
    if (error.status >= 500) return "We couldn't sign you in. Try again later.";
  }
  return "Unable to reach CloudSentinel. Check your connection and try again.";
}

export function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [mfaRequired, setMfaRequired] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    setError("");
    setBusy(true);
    const form = new FormData(event.currentTarget);
    try {
      const challengeRequired = await login(
        String(form.get("email")).trim(),
        String(form.get("password")),
        mfaRequired ? String(form.get("mfa_code")) : undefined,
      );
      if (challengeRequired) {
        setMfaRequired(true);
        return;
      }
      navigate("/", { replace: true });
    } catch (err) {
      setError(
        mfaRequired && err instanceof ApiError && err.status === 401
          ? "The authenticator or recovery code is invalid."
          : loginError(err),
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login-page">
      <section className="login-story" aria-label="CloudSentinel platform">
        <div className="login-brand">
          <AuthBrand />
        </div>
        <div className="login-story-copy">
          <p className="login-kicker">SECURE&nbsp; · &nbsp;MONITOR&nbsp; · &nbsp;COMPLY</p>
          <h1>Enterprise Cloud<br />Security Posture<br /><span>Management</span></h1>
          <p className="login-intro">Protect, assess, and continuously monitor<br className="desktop-break" /> your cloud security posture.</p>
          <ul className="login-benefits">
            <li><span aria-hidden="true"><Icon name="assets" /></span><div>Cloud Asset Visibility<small>Discover and monitor your cloud infrastructure</small></div></li>
            <li><span aria-hidden="true"><Icon name="shield" /></span><div>Security Risk Intelligence<small>Identify and prioritize security risks</small></div></li>
            <li><span aria-hidden="true"><Icon name="check" /></span><div>Compliance Monitoring<small>Stay aligned with industry standards</small></div></li>
          </ul>
        </div>
        <p className="login-copyright">© 2026 CloudSentinel<br />Security Operations Platform</p>
      </section>

      <section className="login-form-side">
        <div className="login-brand login-mobile-brand"><AuthBrand /></div>
        <div className="login-panel">
          <h2>Welcome back</h2>
          <p className="login-subtitle">Sign in to your CloudSentinel account.</p>
          <form onSubmit={submit} className="login-fields" aria-busy={busy}>
            <label htmlFor="login-email">Work email</label>
            <div className="login-input-wrap"><span aria-hidden="true"><Icon name="mail" /></span><input id="login-email" name="email" type="email" autoComplete="username" placeholder="analyst@company.com" required disabled={busy} /></div>

            <label htmlFor="login-password">Password</label>
            <div className="login-input-wrap"><span aria-hidden="true"><Icon name="lock" /></span><input id="login-password" name="password" type={showPassword ? "text" : "password"} autoComplete="current-password" maxLength={128} required disabled={busy} /><button type="button" className="password-toggle" aria-label={showPassword ? "Hide password" : "Show password"} aria-pressed={showPassword} aria-controls="login-password" onClick={() => setShowPassword((value) => !value)} disabled={busy}><Icon name={showPassword ? "eye-off" : "eye"} /></button></div>

            {mfaRequired && <>
              <label htmlFor="login-mfa-code">Authenticator or recovery code</label>
              <div className="login-input-wrap"><span aria-hidden="true"><Icon name="lock" /></span><input id="login-mfa-code" name="mfa_code" type="text" inputMode="text" autoComplete="one-time-code" maxLength={20} required disabled={busy} autoFocus /></div>
              <small className="login-field-hint">Enter the current six-digit code or one unused recovery code.</small>
            </>}

            <div className="login-options"><Link to="/forgot-password">Forgot password?</Link></div>
            {error && <div className="login-error" role="alert">{error}</div>}
            <button className="login-submit" type="submit" disabled={busy}>{busy ? "Signing in…" : <>{mfaRequired ? "Verify and sign in" : "Sign in"} <Icon name="arrow-right" /></>}</button>
          </form>
          <div className="login-security-note"><span aria-hidden="true"><Icon name="lock" /></span><div><strong>Secured enterprise authentication</strong><small>Your credentials are protected with secure session handling.</small></div></div>
        </div>
      </section>
    </main>
  );
}

export function ForgotPasswordPage() {
  const [submitted, setSubmitted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    setError("");
    setBusy(true);
    const form = new FormData(event.currentTarget);
    try {
      await api.forgotPassword(String(form.get("email")).trim());
      setSubmitted(true);
    } catch (reason) {
      if (reason instanceof ApiError && reason.status === 429) {
        setError("Too many requests. Please wait before requesting another reset link.");
      } else if (reason instanceof ApiError && reason.status >= 500) {
        setError("Password recovery is temporarily unavailable. Try again later.");
      } else {
        setError("Unable to submit your request. Check your connection and try again.");
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
          {submitted ? (
            <div className="recovery-success">
              <span className="recovery-icon" aria-hidden="true"><Icon name="mail" /></span>
              <h2>Check your email</h2>
              <p className="login-subtitle">If an account exists for this email, we've sent a password reset link.</p>
              <p className="recovery-expiry">The link expires after a limited time for your security.</p>
              <Link className="login-submit recovery-link" to="/login">Back to sign in</Link>
            </div>
          ) : (
            <>
              <span className="recovery-icon" aria-hidden="true"><Icon name="refresh" /></span>
              <h2>Reset your password</h2>
              <p className="login-subtitle">Enter your work email and we'll send you a secure password reset link.</p>
              <form className="recovery-form" onSubmit={submit} aria-busy={busy}>
                <label htmlFor="recovery-email">Work email</label>
                <div className="login-input-wrap"><span aria-hidden="true"><Icon name="mail" /></span><input id="recovery-email" name="email" type="email" autoComplete="email" placeholder="analyst@company.com" required disabled={busy} /></div>
                {error && <div className="login-error" role="alert">{error}</div>}
                <button className="login-submit" type="submit" disabled={busy}>{busy ? "Sending reset link…" : <>Send reset link <Icon name="arrow-right" /></>}</button>
              </form>
              <Link className="recovery-back" to="/login">← Back to sign in</Link>
            </>
          )}
        </div>
        <p className="recovery-security"><Icon name="lock" /> Secure account recovery</p>
        <p className="recovery-copyright">© 2026 CloudSentinel</p>
      </section>
    </main>
  );
}
