import React from "react";
import Link from "next/link";
import { BrandLogo } from "@/components/ui/brand-logo";

export default function AuthLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="min-h-screen bg-[#06090f] cyber-grid flex flex-col justify-center py-12 sm:px-6 lg:px-8 relative overflow-hidden">
      {/* Background Holographic Glow & Cyber Shields */}
      <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[850px] h-[500px] bg-gradient-to-b from-cyber-blue/15 via-cyber-cyan/10 to-transparent blur-[140px] pointer-events-none" />
      <div className="absolute -top-32 -right-32 w-96 h-96 bg-cyber-blue/10 rounded-full blur-[100px] pointer-events-none" />
      <div className="absolute -bottom-32 -left-32 w-96 h-96 bg-cyber-cyan/10 rounded-full blur-[100px] pointer-events-none" />

      {/* Top Banner Status */}
      <div className="absolute top-6 right-6 hidden sm:flex items-center gap-2.5 px-3.5 py-1.5 rounded-full border border-cyber-cyan/30 bg-background-card/90 backdrop-blur-md text-xs font-mono shadow-glow">
        <span className="w-2 h-2 rounded-full bg-cyber-cyan animate-pulse shadow-[0_0_8px_#00d2ff]"></span>
        <span className="text-slate-200 font-semibold tracking-wider">SECURE ZERO-TRUST GATEWAY</span>
      </div>

      <div className="sm:mx-auto sm:w-full sm:max-w-md text-center z-10 flex flex-col items-center">
        <BrandLogo size="xl" glow={true} linkTo="/login" />
        <p className="mt-3 text-xs font-mono text-slate-400 uppercase tracking-widest">
          Autonomous Offensive & Defensive Security Mesh
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md z-10 px-4 sm:px-0">
        <div className="glass-panel py-8 px-6 shadow-2xl rounded-2xl sm:px-10 border border-[#1e293b] hover:border-cyber-cyan/40 transition-colors duration-300">
          {children}
        </div>
      </div>

      {/* Security Accreditations Footer */}
      <div className="mt-8 text-center z-10 text-[10px] font-mono text-slate-500 uppercase tracking-widest flex items-center justify-center gap-3">
        <span>SOC-2 TYPE II CERTIFIED</span>
        <span className="text-slate-700">•</span>
        <span>FIPS 140-2 LEVEL 3</span>
        <span className="text-slate-700">•</span>
        <span>ZERO-KNOWLEDGE CRYPTO</span>
      </div>
    </div>
  );
}
