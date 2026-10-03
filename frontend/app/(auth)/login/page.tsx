"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { authApi } from "@/lib/api/auth";
import { firebaseAuth } from "@/lib/firebase/auth";
import { useAuthStore } from "@/lib/store/auth-store";
import { toast } from "@/lib/store/toast-store";
import {
  LockClosedIcon,
  ShieldCheckIcon,
  EnvelopeIcon,
  KeyIcon,
  ExclamationTriangleIcon,
} from "@heroicons/react/24/outline";

export default function LoginPage() {
  const router = useRouter();
  const { login } = useAuthStore();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [authMethod, setAuthMethod] = useState<"standard" | "firebase">("standard");

  // Client-side rate-limiting / lockout defense against brute force
  const [failedAttempts, setFailedAttempts] = useState(0);
  const [lockoutTimer, setLockoutTimer] = useState(0);

  useEffect(() => {
    if (lockoutTimer > 0) {
      const interval = setInterval(() => {
        setLockoutTimer((prev) => Math.max(0, prev - 1));
      }, 1000);
      return () => clearInterval(interval);
    }
  }, [lockoutTimer]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (lockoutTimer > 0) {
      toast.error(
        "Access Temporarily Locked",
        `Too many failed attempts. Please wait ${lockoutTimer} seconds before trying again.`
      );
      return;
    }

    const trimmedEmail = email.trim();
    if (!trimmedEmail || !password) {
      toast.error("Required Fields", "Please enter both your email address and password.");
      return;
    }

    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(trimmedEmail)) {
      toast.error("Invalid Email", "Please enter a valid email address.");
      return;
    }

    setLoading(true);

    try {
      if (authMethod === "firebase") {
        // Firebase Authentication Flow
        const fbUser = await firebaseAuth.signInWithEmail(trimmedEmail, password);
        const userData = {
          id: fbUser.uid,
          email: fbUser.email,
          firstName: fbUser.displayName?.split(" ")[0] || "User",
          lastName: fbUser.displayName?.split(" ").slice(1).join(" ") || "",
          role: "Security Operator",
          organization: "CYBERSPLOI Defense Mesh",
        };

        localStorage.setItem("cybersploi_token", fbUser.idToken);
        localStorage.setItem("cybersploi_user", JSON.stringify(userData));
        document.cookie = `cybersploi_token=${encodeURIComponent(fbUser.idToken)}; path=/; max-age=604800; SameSite=Lax`;
        document.cookie = `auth_token=${encodeURIComponent(fbUser.idToken)}; path=/; max-age=604800; SameSite=Lax`;

        login(fbUser.idToken, userData);
        toast.success("Welcome Back", "Signed in successfully with Firebase.");
        window.location.href = "/dashboard";
      } else {
        // Standard Backend Flow
        const data = await authApi.login({ email: trimmedEmail, password });
        if (!data.token) {
          throw new Error("Invalid response received from authentication server.");
        }

        localStorage.setItem("cybersploi_token", data.token);
        localStorage.setItem("cybersploi_user", JSON.stringify(data.user));
        document.cookie = `cybersploi_token=${encodeURIComponent(data.token)}; path=/; max-age=604800; SameSite=Lax`;
        document.cookie = `auth_token=${encodeURIComponent(data.token)}; path=/; max-age=604800; SameSite=Lax`;

        login(data.token, data.user);
        toast.success("Login Successful", "Welcome back to CYBERSPLOI.");
        window.location.href = "/dashboard";
      }
    } catch (err: any) {
      console.error("Login authentication error:", err);
      const newAttempts = failedAttempts + 1;
      setFailedAttempts(newAttempts);

      if (newAttempts >= 5) {
        setLockoutTimer(30);
        toast.error(
          "Security Lockout",
          "5 failed login attempts detected. Form locked for 30 seconds to protect your account."
        );
      } else {
        const errMsg =
          err.response?.data?.message ||
          err.response?.data?.error ||
          err.message ||
          "Incorrect email or password. Please try again.";
        toast.error("Login Failed", errMsg);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Title & Subtitle */}
      <div className="border-b border-[#1e293b] pb-4">
        <div className="flex items-center justify-between">
          <h2 className="text-xl font-bold text-slate-100 font-sans tracking-wide flex items-center gap-2">
            <LockClosedIcon className="w-5 h-5 text-cyber-cyan" />
            Log In
          </h2>
          <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-cyber-blue/15 text-cyber-cyan border border-cyber-cyan/30 font-semibold">
            Secure Sign-In
          </span>
        </div>
        <p className="text-xs text-slate-400 mt-1">
          Enter your email and password to access the security platform.
        </p>
      </div>

      {/* Authentication Mode Selector (Standard / Firebase) */}
      <div className="flex rounded-xl bg-slate-900/90 p-1 border border-slate-800">
        <button
          type="button"
          onClick={() => setAuthMethod("standard")}
          className={`flex-1 py-1.5 text-xs font-medium rounded-lg transition-all ${
            authMethod === "standard"
              ? "bg-cyber-blue/20 text-cyber-cyan border border-cyber-cyan/40 shadow-sm"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          CYBERSPLOI Account
        </button>
        <button
          type="button"
          onClick={() => setAuthMethod("firebase")}
          className={`flex-1 py-1.5 text-xs font-medium rounded-lg transition-all ${
            authMethod === "firebase"
              ? "bg-amber-500/20 text-amber-300 border border-amber-500/40 shadow-sm"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          Firebase Auth
        </button>
      </div>

      {/* Lockout Warning Banner if active */}
      {lockoutTimer > 0 && (
        <div className="p-3 bg-red-950/70 border border-red-500/50 rounded-xl flex items-center gap-2.5 text-red-300 text-xs font-mono animate-pulse">
          <ExclamationTriangleIcon className="w-5 h-5 text-red-400 shrink-0" />
          <div>
            <p className="font-bold">Account temporarily locked</p>
            <p className="text-[11px] text-red-400/90">Please wait {lockoutTimer}s before next attempt.</p>
          </div>
        </div>
      )}

      {/* Main Login Form */}
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-xs font-medium text-slate-300 mb-1.5">Email Address</label>
          <div className="relative">
            <input
              type="email"
              placeholder="name@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={lockoutTimer > 0 || loading}
              required
              className="w-full bg-[#0b101b] border border-slate-800 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyber-cyan focus:ring-1 focus:ring-cyber-cyan transition-all disabled:opacity-50"
            />
          </div>
        </div>

        <div>
          <div className="flex items-center justify-between mb-1.5">
            <label className="block text-xs font-medium text-slate-300">Password</label>
            <Link
              href="/forgot-password"
              onClick={(e) => {
                e.preventDefault();
                if (email) {
                  firebaseAuth.sendPasswordReset(email).then(() => {
                    toast.success("Password Reset", "Password reset instructions sent to your email.");
                  }).catch((err) => {
                    toast.error("Reset Failed", err.message);
                  });
                } else {
                  toast.error("Enter Email", "Please enter your email above to receive reset instructions.");
                }
              }}
              className="text-xs text-cyber-cyan hover:underline"
            >
              Forgot password?
            </Link>
          </div>
          <div className="relative">
            <input
              type="password"
              placeholder="••••••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={lockoutTimer > 0 || loading}
              required
              className="w-full bg-[#0b101b] border border-slate-800 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyber-cyan focus:ring-1 focus:ring-cyber-cyan transition-all disabled:opacity-50"
            />
          </div>
        </div>

        <Button
          type="submit"
          variant="primary"
          className="w-full py-3 text-sm font-semibold tracking-wide mt-2"
          isLoading={loading}
          disabled={lockoutTimer > 0}
        >
          {loading ? "Logging in..." : "Log In"}
        </Button>
      </form>

      {/* Prominent Sign Up CTA Link */}
      <div className="pt-4 border-t border-[#1e293b] text-center space-y-3">
        <p className="text-xs text-slate-400">
          Don't have an account?{" "}
          <Link
            href="/register"
            className="text-cyber-cyan hover:underline font-bold transition-colors"
          >
            Create an Account
          </Link>
        </p>

        <div className="pt-2 flex items-center justify-center gap-4 text-[11px] text-slate-500">
          <Link href="/consent" className="hover:text-slate-300 transition-colors">
            Terms of Service
          </Link>
          <span>•</span>
          <Link href="/consent" className="hover:text-slate-300 transition-colors">
            Privacy Policy
          </Link>
        </div>
      </div>
    </div>
  );
}
