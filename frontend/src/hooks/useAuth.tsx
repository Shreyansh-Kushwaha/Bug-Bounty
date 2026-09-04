import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { api } from "../lib/api";

type AuthState = {
  ready: boolean;
  authEnabled: boolean;
  authed: boolean;
  name: string | null;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
};

const Ctx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [ready, setReady] = useState(false);
  const [authEnabled, setAuthEnabled] = useState(false);
  const [authed, setAuthed] = useState(false);
  const [name, setName] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const me = await api.me();
      setAuthEnabled(me.auth_enabled);
      setAuthed(me.authenticated);
      setName(me.name);
    } catch {
      setAuthEnabled(true);
      setAuthed(false);
    } finally {
      setReady(true);
    }
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } catch {
      /* ignore */
    }
    await refresh();
  }, [refresh]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return (
    <Ctx.Provider value={{ ready, authEnabled, authed, name, refresh, logout }}>
      {children}
    </Ctx.Provider>
  );
}

export function useAuth(): AuthState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAuth must be used within AuthProvider");
  return v;
}
