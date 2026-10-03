"use client";

import React, { useState, useEffect } from "react";
import Image from "next/image";
import Link from "next/link";
import { motion, AnimatePresence } from "framer-motion";
import {
  ShieldCheckIcon,
  CpuChipIcon,
  GlobeAltIcon,
  BoltIcon,
  ArrowRightIcon,
  LockClosedIcon,
  ExclamationTriangleIcon,
  ServerStackIcon,
  ChartBarSquareIcon,
  CheckCircleIcon,
  FingerPrintIcon,
  CommandLineIcon,
} from "@heroicons/react/24/outline";
import { CyberCoreScene } from "@/components/ui/cyber-core-scene";

export default function LandingPage() {
  const [scrollProgress, setScrollProgress] = useState(0);
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });
  const [activeStage, setActiveStage] = useState(0);
  const [isLoaded, setIsLoaded] = useState(false);

  // Track scroll position seamlessly
  useEffect(() => {
    // Initializer loader
    const timer = setTimeout(() => {
      setIsLoaded(true);
    }, 1100);

    const handleScroll = () => {
      const totalScroll =
        document.documentElement.scrollHeight - window.innerHeight;
      if (totalScroll > 0) {
        const currentProgress = window.scrollY / totalScroll;
        setScrollProgress(Math.min(1, Math.max(0, currentProgress)));
      }
    };

    const handleMouseMove = (e: MouseEvent) => {
      setMousePos({
        x: (e.clientX / window.innerWidth - 0.5) * 2,
        y: (e.clientY / window.innerHeight - 0.5) * 2,
      });
    };

    window.addEventListener("scroll", handleScroll, { passive: true });
    window.addEventListener("mousemove", handleMouseMove, { passive: true });

    return () => {
      clearTimeout(timer);
      window.removeEventListener("scroll", handleScroll);
      window.removeEventListener("mousemove", handleMouseMove);
    };
  }, []);

  return (
    <div className="relative bg-[#050609] text-slate-100 min-h-screen selection:bg-cyber-cyan selection:text-slate-950 font-sans overflow-x-hidden">
      {/* 00 — INITIALIZING BOOT SCREEN */}
      <AnimatePresence>
        {!isLoaded && (
          <motion.div
            initial={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.8, ease: "easeInOut" }}
            className="fixed inset-0 z-50 bg-[#050609] flex flex-col items-center justify-center p-6"
          >
            <div className="w-16 h-16 relative mb-6">
              <Image
                src="/shield-logo.png"
                alt="CYBERSPLOI"
                fill
                className="object-contain animate-pulse"
                priority
              />
            </div>
            <p className="font-mono text-xs uppercase tracking-[0.3em] text-cyber-cyan mb-3">
              INITIALIZING SECURITY ENVIRONMENT
            </p>
            <div className="w-48 h-[2px] bg-slate-800 rounded-full overflow-hidden">
              <motion.div
                initial={{ width: "0%" }}
                animate={{ width: "100%" }}
                transition={{ duration: 1, ease: "easeInOut" }}
                className="h-full bg-gradient-to-r from-blue-500 via-cyber-cyan to-emerald-400"
              />
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* PERSISTENT 3D SCENE CANVAS */}
      <CyberCoreScene
        scrollProgress={scrollProgress}
        mousePos={mousePos}
      />

      {/* FLOATING TOP NAVIGATION */}
      <header
        className={`fixed top-0 left-0 right-0 z-40 transition-all duration-300 ${
          scrollProgress > 0.05
            ? "bg-[#050609]/80 backdrop-blur-xl border-b border-slate-800/60 py-3.5 shadow-2xl"
            : "bg-transparent py-6"
        }`}
      >
        <div className="max-w-7xl mx-auto px-6 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-3 group">
            <div className="relative w-8 h-8">
              <Image
                src="/shield-logo.png"
                alt="Cybersploi Shield"
                fill
                className="object-contain transition-transform group-hover:scale-105"
              />
            </div>
            <span className="font-mono font-bold tracking-[0.25em] text-lg text-slate-100 uppercase group-hover:text-cyber-cyan transition-colors">
              CYBERSPLOI
            </span>
          </Link>

          <nav className="hidden md:flex items-center gap-8 text-xs font-mono tracking-wider text-slate-400">
            <a href="#hero" className="hover:text-cyber-cyan transition-colors">
              PLATFORM
            </a>
            <a href="#threats" className="hover:text-cyber-cyan transition-colors">
              INTELLIGENCE
            </a>
            <a href="#how-it-works" className="hover:text-cyber-cyan transition-colors">
              PROTECTION
            </a>
            <a href="#dashboard" className="hover:text-cyber-cyan transition-colors">
              SOLUTIONS
            </a>
            <a href="#enterprise" className="hover:text-cyber-cyan transition-colors">
              COMPANY
            </a>
          </nav>

          <div className="flex items-center gap-3">
            <Link
              href="/login"
              className="text-xs font-mono font-semibold tracking-wider text-slate-300 hover:text-cyber-cyan px-4 py-2 rounded-lg border border-slate-800 hover:border-cyber-cyan/40 bg-slate-900/40 backdrop-blur-md transition-all uppercase"
            >
              LOGIN
            </Link>
            <Link
              href="/register"
              className="relative inline-flex items-center justify-center p-0.5 overflow-hidden text-xs font-mono font-semibold rounded-lg group bg-gradient-to-br from-cyber-cyan via-blue-500 to-indigo-600 group-hover:from-cyber-cyan group-hover:to-blue-500 hover:text-white text-white shadow-glow hover:shadow-glow-lg transition-all"
            >
              <span className="relative px-5 py-2 transition-all ease-in duration-75 bg-[#050609] rounded-md group-hover:bg-opacity-0 tracking-widest uppercase">
                SIGN UP
              </span>
            </Link>
          </div>
        </div>
      </header>

      {/* ========================================================================= */}
      {/* SECTION 01 — HERO */}
      {/* ========================================================================= */}
      <section
        id="hero"
        className="relative min-h-screen flex items-center justify-center px-6 pt-24 pb-16 z-10"
      >
        <div className="max-w-7xl mx-auto w-full grid grid-cols-1 lg:grid-cols-12 gap-12 items-center">
          <div className="lg:col-span-7 flex flex-col items-start space-y-8">
            <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-cyber-cyan/30 bg-cyber-cyan/5 backdrop-blur-md">
              <span className="w-2 h-2 rounded-full bg-cyber-cyan animate-pulse" />
              <span className="text-[11px] font-mono tracking-[0.2em] text-cyber-cyan uppercase">
                AUTONOMOUS SECURITY FABRIC V3.0
              </span>
            </div>

            <h1 className="text-5xl sm:text-6xl md:text-7xl lg:text-8xl font-black tracking-tight uppercase leading-[0.95] text-transparent bg-clip-text bg-gradient-to-b from-white via-slate-100 to-slate-400">
              SECURITY
              <br />
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyber-cyan via-blue-400 to-indigo-400">
                AT THE SPEED
              </span>
              <br />
              OF INTELLIGENCE.
            </h1>

            <p className="text-base sm:text-lg text-slate-400 max-w-xl font-light leading-relaxed">
              Cybersploi helps organizations detect, understand, and respond to
              digital threats before they become business-critical. A seamless
              unification of autonomous agents and verifiable security logic.
            </p>

            <div className="flex flex-col sm:flex-row items-center gap-4 w-full sm:w-auto pt-2">
              <Link
                href="/register"
                className="w-full sm:w-auto px-8 py-4 rounded-xl bg-gradient-to-r from-cyber-cyan to-blue-600 text-slate-950 font-mono font-bold text-xs tracking-[0.15em] uppercase shadow-glow hover:shadow-glow-lg transition-all flex items-center justify-center gap-2 group"
              >
                <span>EXPLORE CYBERSPLOI</span>
                <ArrowRightIcon className="w-4 h-4 transition-transform group-hover:translate-x-1" />
              </Link>
              <a
                href="#threats"
                className="w-full sm:w-auto px-8 py-4 rounded-xl border border-slate-700/80 bg-slate-900/40 hover:bg-slate-800/60 backdrop-blur-md text-slate-300 font-mono text-xs tracking-[0.15em] uppercase transition-all flex items-center justify-center gap-2"
              >
                <span>SEE HOW IT WORKS</span>
              </a>
            </div>
          </div>

          <div className="lg:col-span-5 hidden lg:block" />
        </div>

        {/* Scroll Indicator */}
        <div className="absolute bottom-8 left-1/2 -translate-x-1/2 flex flex-col items-center gap-2 text-slate-500 font-mono text-[10px] tracking-widest uppercase">
          <span>SCROLL TO INITIALIZE</span>
          <div className="w-4 h-7 rounded-full border border-slate-700 flex items-start justify-center p-1">
            <motion.div
              animate={{ y: [0, 10, 0] }}
              transition={{ repeat: Infinity, duration: 1.5, ease: "easeInOut" }}
              className="w-1.5 h-1.5 rounded-full bg-cyber-cyan"
            />
          </div>
        </div>
      </section>

      {/* ========================================================================= */}
      {/* SECTION 02 — THE PROBLEM (Threats Move Fast) */}
      {/* ========================================================================= */}
      <section
        id="threats"
        className="relative min-h-screen flex items-center justify-center px-6 py-28 z-10"
      >
        <div className="max-w-7xl mx-auto w-full">
          <div className="max-w-2xl">
            <span className="text-xs font-mono tracking-[0.25em] text-rose-500 uppercase mb-3 block">
              SECTION 02 — THREAT SURFACE ACCELERATION
            </span>
            <h2 className="text-4xl sm:text-5xl md:text-6xl font-black uppercase tracking-tight text-white mb-4">
              THREATS MOVE FAST.
            </h2>
            <p className="text-2xl sm:text-3xl font-light text-slate-400 mb-8">
              Your defenses should move faster.
            </p>
            <p className="text-slate-400 text-sm leading-relaxed mb-8">
              Legacy defense perimeters operate in static silos while adversaries
              utilize multi-stage automation and autonomous exploitation chains.
              When reaction times are measured in days, breaches are inevitable.
            </p>
          </div>

          {/* Floating Live Telemetry Indicators */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mt-8">
            <div className="p-5 rounded-2xl border border-rose-500/30 bg-rose-950/20 backdrop-blur-xl">
              <div className="flex items-center justify-between mb-3">
                <span className="text-[10px] font-mono tracking-widest text-rose-400 uppercase">
                  ACTIVE ANOMALY
                </span>
                <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping" />
              </div>
              <p className="text-xs font-mono text-slate-300">
                UNAUTHORIZED ACCESS ATTEMPT
              </p>
              <span className="text-[10px] font-mono text-rose-400 mt-2 block">
                RISK LEVEL: CRITICAL
              </span>
            </div>

            <div className="p-5 rounded-2xl border border-amber-500/30 bg-amber-950/20 backdrop-blur-xl">
              <div className="flex items-center justify-between mb-3">
                <span className="text-[10px] font-mono tracking-widest text-amber-400 uppercase">
                  BEHAVIORAL DRIFT
                </span>
                <span className="w-2 h-2 rounded-full bg-amber-500" />
              </div>
              <p className="text-xs font-mono text-slate-300">
                LATERAL API PERMISSION BYPASS
              </p>
              <span className="text-[10px] font-mono text-amber-400 mt-2 block">
                RISK LEVEL: HIGH
              </span>
            </div>

            <div className="p-5 rounded-2xl border border-blue-500/30 bg-blue-950/20 backdrop-blur-xl">
              <div className="flex items-center justify-between mb-3">
                <span className="text-[10px] font-mono tracking-widest text-cyber-cyan uppercase">
                  CONTAINMENT
                </span>
                <ShieldCheckIcon className="w-4 h-4 text-cyber-cyan" />
              </div>
              <p className="text-xs font-mono text-slate-300">
                AUTOMATED ZERO-TRUST QUARANTINE
              </p>
              <span className="text-[10px] font-mono text-cyber-cyan mt-2 block">
                ISOLATION: 100% COMPLETE
              </span>
            </div>

            <div className="p-5 rounded-2xl border border-emerald-500/30 bg-emerald-950/20 backdrop-blur-xl">
              <div className="flex items-center justify-between mb-3">
                <span className="text-[10px] font-mono tracking-widest text-emerald-400 uppercase">
                  NETWORK FABRIC
                </span>
                <CheckCircleIcon className="w-4 h-4 text-emerald-400" />
              </div>
              <p className="text-xs font-mono text-slate-300">
                NEURAL GRAPH HARMONIZATION
              </p>
              <span className="text-[10px] font-mono text-emerald-400 mt-2 block">
                STATUS: RESILIENT
              </span>
            </div>
          </div>
        </div>
      </section>

      {/* ========================================================================= */}
      {/* SECTION 03 — CYBERSPLOI INTELLIGENCE */}
      {/* ========================================================================= */}
      <section className="relative min-h-screen flex items-center justify-center px-6 py-28 z-10">
        <div className="max-w-7xl mx-auto w-full grid grid-cols-1 lg:grid-cols-12 gap-12 items-center">
          <div className="lg:col-span-6 space-y-6">
            <span className="text-xs font-mono tracking-[0.25em] text-cyber-cyan uppercase block">
              SECTION 03 — NEURAL INTELLIGENCE CORE
            </span>
            <h2 className="text-4xl sm:text-5xl md:text-6xl font-black uppercase tracking-tight text-white leading-tight">
              SEE WHAT
              <br />
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyber-cyan to-indigo-400">
                OTHERS MISS.
              </span>
            </h2>
            <p className="text-base sm:text-lg text-slate-400 leading-relaxed font-light">
              Cybersploi turns complex signals into actionable intelligence,
              helping security teams understand what matters before threats
              escalate. By unifying telemetry, auth graphs, and attack vectors,
              hidden pathways are surfaced in milliseconds.
            </p>

            {/* Illustrative Performance Metrics */}
            <div className="grid grid-cols-3 gap-6 pt-6 border-t border-slate-800/80">
              <div>
                <p className="text-3xl sm:text-4xl font-black font-mono text-white">
                  98.7%
                </p>
                <p className="text-[11px] font-mono tracking-wider text-slate-400 uppercase mt-1">
                  THREATS ANALYZED
                </p>
              </div>
              <div>
                <p className="text-3xl sm:text-4xl font-black font-mono text-cyber-cyan">
                  24,812
                </p>
                <p className="text-[11px] font-mono tracking-wider text-slate-400 uppercase mt-1">
                  ANOMALIES DETECTED
                </p>
              </div>
              <div>
                <p className="text-3xl sm:text-4xl font-black font-mono text-emerald-400">
                  4,921
                </p>
                <p className="text-[11px] font-mono tracking-wider text-slate-400 uppercase mt-1">
                  SYSTEMS MONITORED
                </p>
              </div>
            </div>
          </div>

          <div className="lg:col-span-6">
            <div className="p-8 rounded-3xl border border-slate-800 bg-[#080B10]/80 backdrop-blur-2xl shadow-2xl relative overflow-hidden">
              <div className="absolute top-0 right-0 w-48 h-48 bg-cyber-cyan/10 rounded-full blur-3xl pointer-events-none" />
              <div className="flex items-center justify-between pb-6 border-b border-slate-800 mb-6">
                <div className="flex items-center gap-3">
                  <div className="w-3 h-3 rounded-full bg-cyber-cyan animate-pulse" />
                  <span className="font-mono text-xs uppercase tracking-widest text-slate-300">
                    HOLOGRAPHIC SIGNAL RESOLVER
                  </span>
                </div>
                <span className="font-mono text-[10px] text-slate-500 uppercase">
                  LATENCY: 0.42MS
                </span>
              </div>

              <div className="space-y-4">
                <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 flex items-start gap-4">
                  <CpuChipIcon className="w-5 h-5 text-cyber-cyan shrink-0 mt-0.5" />
                  <div>
                    <p className="text-xs font-mono text-slate-200 font-semibold">
                      Graph Neural Pattern Extraction
                    </p>
                    <p className="text-[11px] text-slate-400 mt-1">
                      Correlating 1.2M microservice queries with differential
                      permissions matrix to isolate privilege drifts.
                    </p>
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 flex items-start gap-4">
                  <FingerPrintIcon className="w-5 h-5 text-indigo-400 shrink-0 mt-0.5" />
                  <div>
                    <p className="text-xs font-mono text-slate-200 font-semibold">
                      Deterministic Proof of Exploitability (PoC)
                    </p>
                    <p className="text-[11px] text-slate-400 mt-1">
                      Mathematically verifying exploit reachability without
                      causing unintended service downtime.
                    </p>
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 flex items-start gap-4">
                  <GlobeAltIcon className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                  <div>
                    <p className="text-xs font-mono text-slate-200 font-semibold">
                      Autonomous Defense Convergence
                    </p>
                    <p className="text-[11px] text-slate-400 mt-1">
                      Generating real-time WAF rules, Kubernetes network
                      policies, and least-privilege IAM patches.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ========================================================================= */}
      {/* SECTION 04 — HOW CYBERSPLOI WORKS (From Signal to Response) */}
      {/* ========================================================================= */}
      <section
        id="how-it-works"
        className="relative min-h-screen flex items-center justify-center px-6 py-28 z-10"
      >
        <div className="max-w-7xl mx-auto w-full">
          <div className="text-center max-w-3xl mx-auto mb-16">
            <span className="text-xs font-mono tracking-[0.25em] text-cyber-cyan uppercase mb-3 block">
              SECTION 04 — CONTINUOUS PIPELINE
            </span>
            <h2 className="text-4xl sm:text-5xl md:text-6xl font-black uppercase tracking-tight text-white">
              FROM SIGNAL TO RESPONSE.
            </h2>
            <p className="text-slate-400 text-sm sm:text-base mt-4 font-light">
              Four unified stages of automated defense intelligence working in
              unbroken harmony.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            {[
              {
                num: "01",
                name: "DETECT",
                icon: BoltIcon,
                desc: "Thousands of raw signals and network telemetry streams enter the perimeter in real time.",
                color: "text-blue-400",
                borderColor: "hover:border-blue-500/50",
              },
              {
                num: "02",
                name: "UNDERSTAND",
                icon: CpuChipIcon,
                desc: "Signals are contextualized into meaningful threat patterns and clustered by semantic impact.",
                color: "text-cyber-cyan",
                borderColor: "hover:border-cyber-cyan/50",
              },
              {
                num: "03",
                name: "PRIORITIZE",
                icon: ExclamationTriangleIcon,
                desc: "The system isolates highest-risk attack paths using graph reachability algorithms.",
                color: "text-amber-400",
                borderColor: "hover:border-amber-500/50",
              },
              {
                num: "04",
                name: "RESPOND",
                icon: ShieldCheckIcon,
                desc: "Deterministic response pathways execute instantaneous perimeter hardening and containment.",
                color: "text-emerald-400",
                borderColor: "hover:border-emerald-500/50",
              },
            ].map((stage, idx) => {
              const Icon = stage.icon;
              return (
                <div
                  key={stage.num}
                  onClick={() => setActiveStage(idx)}
                  className={`p-8 rounded-3xl border border-slate-800/80 bg-[#080B10]/70 backdrop-blur-xl transition-all duration-300 cursor-pointer ${
                    activeStage === idx
                      ? "border-cyber-cyan shadow-glow scale-[1.02] bg-[#0c121d]"
                      : "hover:border-slate-700"
                  }`}
                >
                  <div className="flex items-center justify-between mb-8">
                    <span className="font-mono text-2xl font-black text-slate-600">
                      {stage.num}
                    </span>
                    <Icon className={`w-6 h-6 ${stage.color}`} />
                  </div>
                  <h3 className="text-xl font-bold font-mono tracking-wider uppercase text-white mb-3">
                    {stage.name}
                  </h3>
                  <p className="text-xs text-slate-400 leading-relaxed font-light">
                    {stage.desc}
                  </p>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* ========================================================================= */}
      {/* SECTION 05 — PRODUCT EXPERIENCE (Futuristic Dashboard) */}
      {/* ========================================================================= */}
      <section
        id="dashboard"
        className="relative min-h-screen flex items-center justify-center px-6 py-28 z-10"
      >
        <div className="max-w-7xl mx-auto w-full">
          <div className="text-center max-w-2xl mx-auto mb-12">
            <span className="text-xs font-mono tracking-[0.25em] text-cyber-cyan uppercase mb-3 block">
              SECTION 05 — PLATFORM CAPABILITIES
            </span>
            <h2 className="text-4xl sm:text-5xl font-black uppercase tracking-tight text-white">
              COMMAND THE UNSEEN.
            </h2>
            <p className="text-slate-400 text-sm mt-3 font-light">
              High-resolution control over global infrastructure, threat graphs,
              and automated mitigation pipelines.
            </p>
          </div>

          {/* Futuristic Command Panel Mockup */}
          <div className="rounded-3xl border border-slate-800 bg-[#080B10]/90 backdrop-blur-2xl shadow-2xl p-6 sm:p-8">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-5 mb-6">
              <div className="flex items-center gap-3">
                <div className="flex gap-1.5">
                  <div className="w-3 h-3 rounded-full bg-rose-500/80" />
                  <div className="w-3 h-3 rounded-full bg-amber-500/80" />
                  <div className="w-3 h-3 rounded-full bg-emerald-500/80" />
                </div>
                <span className="font-mono text-xs text-slate-400 uppercase tracking-widest pl-3 border-l border-slate-800">
                  CYBERSPLOI SECURITY SUITE — LIVE OPERATIONS
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyber-cyan animate-pulse" />
                <span className="font-mono text-xs text-cyber-cyan uppercase">
                  AGENT RUNNER ONLINE
                </span>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* Left Column: Attack Vector Map */}
              <div className="lg:col-span-8 p-6 rounded-2xl bg-slate-900/60 border border-slate-800/80 space-y-4">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs tracking-wider text-slate-300 uppercase flex items-center gap-2">
                    <ChartBarSquareIcon className="w-4 h-4 text-cyber-cyan" />
                    Global Threat Landscape & Exposure Graph
                  </span>
                  <span className="font-mono text-[10px] text-slate-500">
                    REALTIME FEED
                  </span>
                </div>
                <div className="h-64 rounded-xl border border-slate-800/80 bg-[#050609] p-4 flex flex-col justify-between font-mono text-xs">
                  <div className="flex justify-between items-center text-[10px] text-slate-500">
                    <span>ASSET // PROD-US-EAST-K8S</span>
                    <span className="text-emerald-400">DEFENSE VERIFIED</span>
                  </div>
                  <div className="flex items-end justify-between h-40 gap-2 px-4">
                    {[45, 78, 32, 95, 60, 85, 40, 70, 90, 55, 30, 88].map(
                      (h, i) => (
                        <div
                          key={i}
                          className="w-full bg-slate-800 rounded-t hover:bg-cyber-cyan transition-colors group relative"
                          style={{ height: `${h}%` }}
                        >
                          <div className="hidden group-hover:block absolute -top-7 left-1/2 -translate-x-1/2 bg-slate-900 border border-slate-700 px-2 py-0.5 rounded text-[9px] text-white">
                            {h}%
                          </div>
                        </div>
                      )
                    )}
                  </div>
                  <div className="flex justify-between text-[10px] text-slate-500 pt-2 border-t border-slate-800">
                    <span>T-60 MIN</span>
                    <span>T-30 MIN</span>
                    <span>CURRENT CYCLE</span>
                  </div>
                </div>
              </div>

              {/* Right Column: Live Incident Log */}
              <div className="lg:col-span-4 p-6 rounded-2xl bg-slate-900/60 border border-slate-800/80 space-y-4">
                <span className="font-mono text-xs tracking-wider text-slate-300 uppercase flex items-center gap-2">
                  <CommandLineIcon className="w-4 h-4 text-cyber-cyan" />
                  Telemetry Log Stream
                </span>

                <div className="space-y-3 font-mono text-[11px]">
                  <div className="p-3 rounded-lg bg-[#050609] border border-slate-800/70">
                    <div className="flex justify-between text-[10px] text-slate-500 mb-1">
                      <span>04:22:15 UTC</span>
                      <span className="text-rose-400">BLOCKED</span>
                    </div>
                    <p className="text-slate-300">
                      Cross-Tenant SQLi probe neutralized by ScopeGuard.
                    </p>
                  </div>

                  <div className="p-3 rounded-lg bg-[#050609] border border-slate-800/70">
                    <div className="flex justify-between text-[10px] text-slate-500 mb-1">
                      <span>04:21:40 UTC</span>
                      <span className="text-cyber-cyan">RETEST</span>
                    </div>
                    <p className="text-slate-300">
                      AuthMatrixAgent validated OAuth session revocation.
                    </p>
                  </div>

                  <div className="p-3 rounded-lg bg-[#050609] border border-slate-800/70">
                    <div className="flex justify-between text-[10px] text-slate-500 mb-1">
                      <span>04:20:02 UTC</span>
                      <span className="text-emerald-400">PASSED</span>
                    </div>
                    <p className="text-slate-300">
                      CI/CD Pipeline #37086435646 build & security test pass.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ========================================================================= */}
      {/* SECTION 06 — THE NETWORK (One Intelligence Layer) */}
      {/* ========================================================================= */}
      <section className="relative min-h-screen flex items-center justify-center px-6 py-28 z-10">
        <div className="max-w-5xl mx-auto w-full text-center space-y-8">
          <span className="text-xs font-mono tracking-[0.25em] text-cyber-cyan uppercase block">
            SECTION 06 — OMNIPRESENT PROTECTION
          </span>

          <h2 className="text-5xl sm:text-6xl md:text-7xl font-black uppercase tracking-tight text-white leading-none">
            ONE INTELLIGENCE LAYER.
            <br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyber-cyan via-blue-400 to-indigo-400">
              EVERY DIGITAL SURFACE.
            </span>
          </h2>

          <p className="text-base sm:text-lg text-slate-400 font-light max-w-2xl mx-auto leading-relaxed">
            From bare-metal hypervisors to serverless edge functions and
            distributed Kubernetes nodes, Cybersploi wraps your entire ecosystem
            in an adaptive, self-healing cryptographic barrier.
          </p>

          <div className="pt-8 flex flex-wrap items-center justify-center gap-4 text-xs font-mono text-slate-400">
            {[
              "DATACENTERS",
              "CLOUD MESH",
              "HYBRID ENDPOINTS",
              "ZERO-TRUST IDENTITY",
              "API SURFACES",
              "DISTRIBUTED DATASETS",
            ].map((surface) => (
              <span
                key={surface}
                className="px-5 py-2.5 rounded-full border border-slate-800 bg-[#080B10]/80 backdrop-blur-md hover:border-cyber-cyan/50 hover:text-white transition-colors"
              >
                {surface}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* ========================================================================= */}
      {/* SECTION 07 — TRUST / ENTERPRISE (Built for What Cannot Fail) */}
      {/* ========================================================================= */}
      <section
        id="enterprise"
        className="relative min-h-screen flex items-center justify-center px-6 py-28 z-10"
      >
        <div className="max-w-7xl mx-auto w-full">
          <div className="max-w-3xl mb-16">
            <span className="text-xs font-mono tracking-[0.25em] text-slate-500 uppercase mb-3 block">
              SECTION 07 — MISSION-CRITICAL ASSURANCE
            </span>
            <h2 className="text-4xl sm:text-5xl md:text-6xl font-black uppercase tracking-tight text-white">
              BUILT FOR THE SYSTEMS
              <br />
              THAT CANNOT FAIL.
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {[
              {
                title: "CLOUD ARCHITECTURE",
                icon: ServerStackIcon,
                desc: "Immutable infrastructure validation across AWS, GCP, and Azure with continuous policy enforcement.",
              },
              {
                title: "FEDERATED IDENTITIES",
                icon: LockClosedIcon,
                desc: "High-speed OAuth, SAML, and WebAuthn credential boundary verification with anomaly dampening.",
              },
              {
                title: "CRITICAL DATA FABRIC",
                icon: ShieldCheckIcon,
                desc: "Zero-knowledge encryption validation and SQL/NoSQL transaction auditing in strict real-time.",
              },
            ].map((card, i) => {
              const Icon = card.icon;
              return (
                <div
                  key={i}
                  className="p-8 rounded-3xl border border-slate-800/80 bg-[#080B10]/50 backdrop-blur-xl hover:border-slate-700 transition-colors"
                >
                  <Icon className="w-8 h-8 text-slate-300 mb-6" />
                  <h3 className="font-mono text-lg font-bold text-white uppercase tracking-wider mb-2">
                    {card.title}
                  </h3>
                  <p className="text-slate-400 text-xs leading-relaxed font-light">
                    {card.desc}
                  </p>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* ========================================================================= */}
      {/* SECTION 08 & 09 — FINAL STATEMENT & CTA */}
      {/* ========================================================================= */}
      <section className="relative min-h-screen flex items-center justify-center px-6 py-28 z-10 text-center">
        <div className="max-w-4xl mx-auto w-full space-y-8">
          <div className="w-16 h-16 relative mx-auto mb-6">
            <Image
              src="/shield-logo.png"
              alt="Cybersploi Core"
              fill
              className="object-contain"
            />
          </div>

          <p className="text-xs font-mono tracking-[0.3em] text-cyber-cyan uppercase">
            THE FUTURE OF DIGITAL DEFENSE
          </p>

          <h2 className="text-5xl sm:text-6xl md:text-7xl font-black uppercase tracking-tight text-white leading-none">
            YOUR DIGITAL WORLD
            <br />
            IS ALWAYS MOVING.
            <br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyber-cyan via-blue-400 to-indigo-400">
              SO SHOULD YOUR SECURITY.
            </span>
          </h2>

          <div className="pt-6 flex flex-col sm:flex-row items-center justify-center gap-4">
            <Link
              href="/register"
              className="w-full sm:w-auto px-10 py-5 rounded-xl bg-gradient-to-r from-cyber-cyan to-blue-600 text-slate-950 font-mono font-bold text-xs tracking-[0.2em] uppercase shadow-glow hover:shadow-glow-lg transition-all"
            >
              START WITH CYBERSPLOI
            </Link>
            <Link
              href="/login"
              className="w-full sm:w-auto px-10 py-5 rounded-xl border border-slate-700 bg-slate-900/60 hover:bg-slate-800 text-white font-mono text-xs tracking-[0.2em] uppercase transition-all"
            >
              EXPLORE THE PLATFORM
            </Link>
          </div>
        </div>
      </section>

      {/* ========================================================================= */}
      {/* FOOTER */}
      {/* ========================================================================= */}
      <footer className="relative border-t border-slate-900 bg-[#050609] py-14 px-6 z-10">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-8">
          <div className="flex items-center gap-3">
            <div className="relative w-7 h-7">
              <Image
                src="/shield-logo.png"
                alt="Cybersploi Shield"
                fill
                className="object-contain"
              />
            </div>
            <span className="font-mono font-bold tracking-[0.2em] text-sm text-slate-100 uppercase">
              CYBERSPLOI
            </span>
          </div>

          <div className="flex items-center gap-8 text-xs font-mono text-slate-400">
            <a href="#hero" className="hover:text-cyber-cyan transition-colors">
              Platform
            </a>
            <a href="#threats" className="hover:text-cyber-cyan transition-colors">
              Solutions
            </a>
            <a href="#how-it-works" className="hover:text-cyber-cyan transition-colors">
              Intelligence
            </a>
            <a href="#enterprise" className="hover:text-cyber-cyan transition-colors">
              Company
            </a>
            <Link href="/login" className="hover:text-cyber-cyan transition-colors">
              Contact
            </Link>
          </div>

          <p className="text-xs font-mono text-slate-600">
            &copy; 2026 CYBERSPLOI INC. ALL RIGHTS RESERVED.
          </p>
        </div>
      </footer>
    </div>
  );
}
