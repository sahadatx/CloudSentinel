import { useEffect, useMemo, useState } from "react";
import { api, setAccessToken, type User } from "./api";
import { AuthContext, type AuthContextValue } from "./auth-context";

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    api
      .refresh()
      .then((result) => {
        if (result) {
          setAccessToken(result.access_token);
          setUser(result.user);
        }
      })
      .catch(() => undefined)
      .finally(() => setReady(true));
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      ready,
      async login(email, password, mfaCode) {
        const result = await api.login(email, password, mfaCode);
        if ("mfa_required" in result) return true;
        setAccessToken(result.access_token);
        setUser(result.user);
        return false;
      },
      async completeSso(code) {
        const result = await api.exchangeSsoCode(code);
        setAccessToken(result.access_token);
        setUser(result.user);
      },
      async changePassword(currentPassword, newPassword) {
        await api.changePassword(currentPassword, newPassword);
        setUser((current) =>
          current ? { ...current, force_password_change: false } : current,
        );
      },
      async updateDisplayName(displayName) {
        const updated = await api.patch<User>("/users/me", { display_name: displayName });
        setUser((current) => current ? { ...current, display_name: updated.display_name } : current);
      },
      clearLocalSession() {
        setAccessToken(null);
        setUser(null);
      },
      async logout() {
        try {
          await api.logout();
        } finally {
          setAccessToken(null);
          setUser(null);
        }
      },
    }),
    [user, ready],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
