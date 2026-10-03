"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { authApi } from "@/lib/api/auth";
import { firebaseAuth } from "@/lib/firebase/auth";
import { useAuthStore } from "@/lib/store/auth-store";
import { toast } from "@/lib/store/toast-store";
import {
  UserPlusIcon,
  ShieldCheckIcon,
  CheckCircleIcon,
  ExclamationCircleIcon,
} from "@heroicons/react/24/outline";

export default function RegisterPage() {
  const router = useRouter();
  const { login } = useAuthStore();
  const [formData, setFormData] = useState({
    firstName: "",
    lastName: "",
    organizationName: "",
    email: "",
    password: "",
  });
  const [loading, setLoading] = useState(false);
  const [authMethod, setAuthMethod] = useState<"standard" | "firebase">("standard");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const trimmedEmail = formData.email.trim();
    if (!formData.firstName || !formData.lastName || !trimmedEmail || !formData.password) {
      toast.error("Required Fields", "Please fill in all required fields.");
      return;
    }

    if (formData.password.length < 8) {
      toast.error("Weak Password", "Password must be at least 8 characters long.");
      return;
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(trimmedEmail)) {
      toast.error("Invalid Email", "Please enter a valid email address.");
      return;
    }

    setLoading(true);

    try {
      if (authMethod === "firebase") {
        // Firebase Sign Up
        const fullName = `${formData.firstName} ${formData.lastName}`.trim();
        const fbUser = await firebaseAuth.signUpWithEmail(trimmedEmail, formData.password, fullName);
        const userData = {
          id: fbUser.uid,
          email: fbUser.email,
          firstName: formData.firstName,
          lastName: formData.lastName,
          role: "Security Administrator",
          organizationName: formData.organizationName || "Independent Organization",
          organization: formData.organizationName || "Independent Organization",
        };

        localStorage.setItem("cybersploi_token", fbUser.idToken);
        localStorage.setItem("cybersploi_user", JSON.stringify(userData));
        document.cookie = `cybersploi_token=${encodeURIComponent(fbUser.idToken)}; path=/; max-age=604800; SameSite=Lax`;
        document.cookie = `auth_token=${encodeURIComponent(fbUser.idToken)}; path=/; max-age=604800; SameSite=Lax`;

        login(fbUser.idToken, userData);
        toast.success("Account Created", "Your Firebase account is ready.");
        window.location.href = "/consent";
      } else {
        // Standard Backend Sign Up
        const data = await authApi.register({
          ...formData,
          email: trimmedEmail,
        });

        if (!data.token) {
          throw new Error("Registration succeeded but did not return a session token.");
        }

        localStorage.setItem("cybersploi_token", data.token);
        localStorage.setItem("cybersploi_user", JSON.stringify(data.user));
        document.cookie = `cybersploi_token=${encodeURIComponent(data.token)}; path=/; max-age=604800; SameSite=Lax`;
        document.cookie = `auth_token=${encodeURIComponent(data.token)}; path=/; max-age=604800; SameSite=Lax`;

        login(data.token, data.user);
        toast.success("Account Created", "Your account has been set up successfully.");
        window.location.href = "/consent";
      }
    } catch (err: any) {
      console.error("Registration error:", err);
      const errMsg =
        err.response?.data?.message ||
        err.response?.data?.error ||
        err.message ||
        "Could not create account. Please check your information.";
      toast.error("Registration Failed", errMsg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="border-b border-[#1e293b] pb-4">
        <div className="flex items-center justify-between">
          <h2 className="text-xl font-bold text-slate-100 font-sans tracking-wide flex items-center gap-2">
            <UserPlusIcon className="w-5 h-5 text-cyber-cyan" />
            Create an Account
          </h2>
          <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-cyber-blue/15 text-cyber-cyan border border-cyber-cyan/30 font-semibold">
            Registration
          </span>
        </div>
        <p className="text-xs text-slate-400 mt-1">
          Sign up to begin securing and monitoring your infrastructure.
        </p>
      </div>

      {/* Mode Selector */}
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
          Standard Registration
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

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">First Name</label>
            <input
              type="text"
              placeholder="Jane"
              value={formData.firstName}
              onChange={(e) => setFormData({ ...formData, firstName: e.target.value })}
              required
              className="w-full bg-[#0b101b] border border-slate-800 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyber-cyan focus:ring-1 focus:ring-cyber-cyan transition-all"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">Last Name</label>
            <input
              type="text"
              placeholder="Doe"
              value={formData.lastName}
              onChange={(e) => setFormData({ ...formData, lastName: e.target.value })}
              required
              className="w-full bg-[#0b101b] border border-slate-800 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyber-cyan focus:ring-1 focus:ring-cyber-cyan transition-all"
            />
          </div>
        </div>

        <div>
          <label className="block text-xs font-medium text-slate-300 mb-1.5">Company / Organization</label>
          <input
            type="text"
            placeholder="Acme Defense Inc."
            value={formData.organizationName}
            onChange={(e) => setFormData({ ...formData, organizationName: e.target.value })}
            required
            className="w-full bg-[#0b101b] border border-slate-800 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyber-cyan focus:ring-1 focus:ring-cyber-cyan transition-all"
          />
        </div>

        <div>
          <label className="block text-xs font-medium text-slate-300 mb-1.5">Email Address</label>
          <input
            type="email"
            placeholder="jane@acmedefense.com"
            value={formData.email}
            onChange={(e) => setFormData({ ...formData, email: e.target.value })}
            required
            className="w-full bg-[#0b101b] border border-slate-800 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyber-cyan focus:ring-1 focus:ring-cyber-cyan transition-all"
          />
        </div>

        <div>
          <label className="block text-xs font-medium text-slate-300 mb-1.5">
            Password <span className="text-slate-500 font-normal">(min 8 characters)</span>
          </label>
          <input
            type="password"
            placeholder="••••••••••••"
            value={formData.password}
            onChange={(e) => setFormData({ ...formData, password: e.target.value })}
            required
            minLength={8}
            className="w-full bg-[#0b101b] border border-slate-800 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyber-cyan focus:ring-1 focus:ring-cyber-cyan transition-all"
          />
        </div>

        <Button
          type="submit"
          variant="primary"
          className="w-full py-3 text-sm font-semibold tracking-wide mt-2"
          isLoading={loading}
        >
          {loading ? "Creating Account..." : "Create Account"}
        </Button>
      </form>

      <div className="pt-4 border-t border-[#1e293b] text-center space-y-2">
        <p className="text-xs text-slate-400">
          Already have an account?{" "}
          <Link
            href="/login"
            className="text-cyber-cyan hover:underline font-bold transition-colors"
          >
            Log In
          </Link>
        </p>
      </div>
    </div>
  );
}
