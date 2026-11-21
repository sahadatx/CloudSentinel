import { createContext } from "react";
import type { User } from "./api";

export type AuthContextValue = {
  user: User | null;
  ready: boolean;
  login: (
    email: string,
    password: string,
    mfaCode?: string,
  ) => Promise<boolean>;
  completeSso: (code: string) => Promise<void>;
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
  updateDisplayName: (displayName: string) => Promise<void>;
  clearLocalSession: () => void;
  logout: () => Promise<void>;
};

export const AuthContext = createContext<AuthContextValue | null>(null);
