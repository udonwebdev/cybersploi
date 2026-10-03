"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { useAuthStore } from "@/lib/store/auth-store";
import { toast } from "@/lib/store/toast-store";
import { ShieldCheckIcon } from "@heroicons/react/24/outline";

export default function ConsentPage() {
  const router = useRouter();
  const { setConsent } = useAuthStore();
  const [agreedTerms, setAgreedTerms] = useState(false);
  const [agreedOwnership, setAgreedOwnership] = useState(false);
  const [agreedResponsible, setAgreedResponsible] = useState(false);

  const canProceed = agreedTerms && agreedOwnership && agreedResponsible;

  const handleConfirm = () => {
    if (!canProceed) return;
    setConsent(true);
    toast.success("Consent Recorded", "Welcome to CYBERSPLOI.");
    router.push("/dashboard");
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 border-b border-[#1e293b] pb-4">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-b from-[#162032] to-[#070b14] border border-cyber-cyan/40 flex items-center justify-center p-1.5 shadow-glow">
          <img
            src="/shield-logo.png"
            alt="Logo"
            className="w-full h-full object-contain filter drop-shadow-[0_0_6px_#00d2ff]"
          />
        </div>
        <div>
          <h2 className="text-lg font-bold text-slate-100 font-sans tracking-wide">
            Terms of Service & Testing Agreement
          </h2>
          <span className="text-xs text-slate-400">
            Please review and agree to terms before running scans
          </span>
        </div>
      </div>

      <div className="bg-[#0b101b] p-4 rounded-xl border border-slate-800 text-xs text-slate-300 leading-relaxed max-h-48 overflow-y-auto space-y-2.5">
        <p className="font-semibold text-cyber-cyan">Security & Ownership Notice:</p>
        <p>
          Before using the CYBERSPLOI vulnerability scanning and automated testing tools, you agree that:
        </p>
        <ul className="list-disc pl-4 space-y-1.5 text-slate-400">
          <li>You own or have written permission from the owner to test all targets, domains, and IP addresses you enter.</li>
          <li>All automated security tests and assessments will be kept within authorized target scopes.</li>
          <li>You agree to use this platform in accordance with applicable cybersecurity laws and industry standards.</li>
        </ul>
      </div>

      <div className="space-y-3 pt-2">
        <label className="flex items-start gap-3 text-xs text-slate-300 cursor-pointer">
          <input
            type="checkbox"
            checked={agreedOwnership}
            onChange={(e) => setAgreedOwnership(e.target.checked)}
            className="mt-0.5 rounded border-slate-700 bg-slate-900 text-cyber-cyan focus:ring-cyber-cyan"
          />
          <span>I certify that my organization owns or has permission to test all submitted target assets.</span>
        </label>

        <label className="flex items-start gap-3 text-xs text-slate-300 cursor-pointer">
          <input
            type="checkbox"
            checked={agreedTerms}
            onChange={(e) => setAgreedTerms(e.target.checked)}
            className="mt-0.5 rounded border-slate-700 bg-slate-900 text-cyber-cyan focus:ring-cyber-cyan"
          />
          <span>I have read and agree to the CYBERSPLOI Terms of Service and Privacy Policy.</span>
        </label>

        <label className="flex items-start gap-3 text-xs text-slate-300 cursor-pointer">
          <input
            type="checkbox"
            checked={agreedResponsible}
            onChange={(e) => setAgreedResponsible(e.target.checked)}
            className="mt-0.5 rounded border-slate-700 bg-slate-900 text-cyber-cyan focus:ring-cyber-cyan"
          />
          <span>I understand that scanning unauthorized targets is strictly prohibited.</span>
        </label>
      </div>

      <Button
        variant="primary"
        className="w-full py-3 text-sm font-semibold"
        disabled={!canProceed}
        onClick={handleConfirm}
      >
        I Agree & Continue to Dashboard
      </Button>
    </div>
  );
}
