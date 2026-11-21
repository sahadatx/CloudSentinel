import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { useAuth } from "../shared/useAuth";

export function SsoCallbackPage() {
  const [params] = useSearchParams();
  const { completeSso } = useAuth();
  const navigate = useNavigate();
  const code = params.get("code");
  const [error, setError] = useState(() =>
    code ? "" : "The single sign-on response is missing or has expired.",
  );
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    window.history.replaceState({}, document.title, "/sso/callback");
    if (!code) return;
    void completeSso(code)
      .then(() => navigate("/", { replace: true }))
      .catch(() => setError("We could not complete sign-in. Start again from your organization’s identity provider."));
  }, [code, completeSso, navigate, params]);

  return (
    <main className="loading-screen">
      {error ? <><span>{error}</span><Link to="/login">Return to sign in</Link></> : <>Completing secure sign-in…</>}
    </main>
  );
}
