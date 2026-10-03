"use client";

import { useEffect } from "react";
import { useAuthStore } from "@/lib/store/auth-store";

export function AuthInitializer() {
  const initAuth = useAuthStore((s) => s.initAuth);

  useEffect(() => {
    initAuth();
  }, [initAuth]);

  return null;
}
