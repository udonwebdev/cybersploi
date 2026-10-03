import { create } from "zustand";

export interface User {
  id: string;
  email: string;
  firstName?: string;
  lastName?: string;
  role: string;
  organizationId?: string;
  organizationName?: string;
  organization?: string;
}

interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  hasConsented: boolean;
  isHydrated: boolean;
  initAuth: () => void;
  login: (token: string, user: User) => void;
  logout: () => void;
  setConsent: (consent: boolean) => void;
  setOrg: (orgId: string, orgName: string) => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  token: null,
  isAuthenticated: false,
  hasConsented: true,
  isHydrated: false,

  initAuth: () => {
    if (typeof window === "undefined") return;
    try {
      const storedToken = localStorage.getItem("cybersploi_token");
      const storedUser = localStorage.getItem("cybersploi_user");
      const storedConsent = localStorage.getItem("cybersploi_consent");

      let user: User | null = null;
      if (storedUser) {
        try {
          user = JSON.parse(storedUser);
        } catch {
          user = null;
        }
      }

      const token = storedToken || null;
      const hasConsented = storedConsent === null ? true : storedConsent === "true";

      set({
        user,
        token,
        isAuthenticated: !!token,
        hasConsented,
        isHydrated: true,
      });
    } catch {
      set({ isHydrated: true });
    }
  },

  login: (token, user) => {
    if (typeof window !== "undefined") {
      localStorage.setItem("cybersploi_token", token);
      localStorage.setItem("cybersploi_user", JSON.stringify(user));
      document.cookie = `cybersploi_token=${encodeURIComponent(token)}; path=/; max-age=604800; SameSite=Lax`;
      document.cookie = `auth_token=${encodeURIComponent(token)}; path=/; max-age=604800; SameSite=Lax`;
    }
    set({ token, user, isAuthenticated: true, isHydrated: true });
  },

  logout: () => {
    if (typeof window !== "undefined") {
      localStorage.removeItem("cybersploi_token");
      localStorage.removeItem("cybersploi_user");
      document.cookie = "cybersploi_token=; path=/; max-age=0; SameSite=Lax";
      document.cookie = "auth_token=; path=/; max-age=0; SameSite=Lax";
    }
    set({ token: null, user: null, isAuthenticated: false, isHydrated: true });
  },

  setConsent: (hasConsented) => {
    if (typeof window !== "undefined") {
      localStorage.setItem("cybersploi_consent", hasConsented ? "true" : "false");
    }
    set({ hasConsented });
  },

  setOrg: (organizationId, organizationName) => {
    set((state) => {
      if (!state.user) return state;
      const updatedUser = { ...state.user, organizationId, organizationName };
      if (typeof window !== "undefined") {
        localStorage.setItem("cybersploi_user", JSON.stringify(updatedUser));
      }
      return { user: updatedUser };
    });
  },
}));
