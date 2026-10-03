"use client";

import React from "react";
import Image from "next/image";
import Link from "next/link";
import clsx from "clsx";

export interface BrandLogoProps {
  size?: "xs" | "sm" | "md" | "lg" | "xl";
  showText?: boolean;
  tagline?: string;
  className?: string;
  glow?: boolean;
  linkTo?: string;
}

const sizeConfig = {
  xs: { img: 22, text: "text-xs", badge: "text-[7px]", gap: "gap-1.5" },
  sm: { img: 28, text: "text-sm", badge: "text-[8px]", gap: "gap-2" },
  md: { img: 36, text: "text-base", badge: "text-[9px]", gap: "gap-2.5" },
  lg: { img: 48, text: "text-xl", badge: "text-[10px]", gap: "gap-3" },
  xl: { img: 72, text: "text-3xl", badge: "text-xs", gap: "gap-4" },
};

export const BrandLogo: React.FC<BrandLogoProps> = ({
  size = "md",
  showText = true,
  tagline,
  className = "",
  glow = true,
  linkTo,
}) => {
  const config = sizeConfig[size];

  const content = (
    <div className={clsx("inline-flex items-center group select-none", config.gap, className)}>
      {/* 3D Shield Hologram Icon */}
      <div className="relative shrink-0 flex items-center justify-center">
        {glow && (
          <div
            className="absolute inset-0 bg-gradient-to-r from-cyber-blue via-cyber-cyan to-white/40 rounded-full blur-md opacity-70 group-hover:opacity-100 group-hover:scale-125 transition-all duration-300"
            style={{ width: config.img * 1.1, height: config.img * 1.1 }}
          />
        )}
        <div
          className={clsx(
            "relative flex items-center justify-center rounded-xl bg-gradient-to-b from-[#0e1726] to-[#06090f] border border-cyber-cyan/30 shadow-glow group-hover:border-cyber-cyan/70 transition-all duration-300 overflow-hidden",
            glow && "group-hover:shadow-glow-lg"
          )}
          style={{ width: config.img, height: config.img, padding: Math.max(2, Math.floor(config.img * 0.08)) }}
        >
          <img
            src="/shield-logo.png"
            alt="CYBERSPLOI Shield"
            width={config.img}
            height={config.img}
            className="w-full h-full object-contain filter drop-shadow-[0_0_8px_rgba(0,210,255,0.7)] group-hover:scale-110 transition-transform duration-300"
          />
          {/* Subtle Cyber Shimmer Glint */}
          <div className="absolute inset-0 bg-gradient-to-tr from-transparent via-white/10 to-transparent pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
        </div>
      </div>

      {/* Brand Typography */}
      {showText && (
        <div className="flex flex-col min-w-0">
          <div className="flex items-center gap-1.5 leading-none">
            <span
              className={clsx(
                "font-mono font-black tracking-wider text-slate-100 uppercase",
                config.text
              )}
            >
              CYBER<span className="text-cyber-cyan text-glow-cyan">SPLOI</span>
            </span>
            <span
              className={clsx(
                "font-mono font-semibold px-1.5 py-0.5 rounded bg-cyber-blue/15 border border-cyber-blue/40 text-cyber-cyan uppercase tracking-widest",
                config.badge
              )}
            >
              PRO
            </span>
          </div>
          {tagline ? (
            <span
              className={clsx(
                "text-slate-400 font-mono tracking-widest uppercase mt-0.5 truncate",
                config.badge
              )}
            >
              {tagline}
            </span>
          ) : (
            <span
              className={clsx(
                "text-slate-500 font-mono tracking-widest uppercase mt-0.5 truncate",
                config.badge
              )}
            >
              DEFENSE MESH v4.5
            </span>
          )}
        </div>
      )}
    </div>
  );

  if (linkTo) {
    return (
      <Link href={linkTo} className="inline-flex">
        {content}
      </Link>
    );
  }

  return content;
};
export default BrandLogo;
