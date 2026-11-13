import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import {
  currentUser,
  login as loginRequest,
  logoutToken,
  saveToken,
  type AuthUser,
} from "./api";

interface AuthContextValue {
  user: AuthUser | null;
  loading: boolean;
  error: string;
  signIn: (username: string, password: string) => Promise<void>;
  signOut: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const signOut = useCallback(() => {
    logoutToken();
    setUser(null);
    setError("");
  }, []);

  useEffect(() => {
    let active = true;
    const expire = () => signOut();
    window.addEventListener("afterlife-auth-expired", expire);
    if (!sessionStorage.getItem("afterlife.access-token")) {
      setLoading(false);
    } else {
      currentUser()
        .then((authenticatedUser) => {
          if (active) setUser(authenticatedUser);
        })
        .catch(() => {
          if (active) signOut();
        })
        .finally(() => {
          if (active) setLoading(false);
        });
    }
    return () => {
      active = false;
      window.removeEventListener("afterlife-auth-expired", expire);
    };
  }, [signOut]);

  const signIn = useCallback(async (username: string, password: string) => {
    setError("");
    try {
      const session = await loginRequest(username, password);
      saveToken(session.access_token);
      setUser(session.user);
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : "Sign-in failed.";
      setError(message);
      throw reason;
    }
  }, []);

  const value = useMemo(
    () => ({ user, loading, error, signIn, signOut }),
    [user, loading, error, signIn, signOut],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used within AuthProvider");
  return context;
}
