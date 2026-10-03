import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./lib/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: {
          DEFAULT: "#06090f",
          subtle: "#0a0e17",
          card: "#0f1623",
          elevated: "#161f30",
          highlight: "#1e293b",
        },
        border: {
          DEFAULT: "#1e293b",
          muted: "#162032",
          active: "#00d2ff",
          glow: "rgba(0, 210, 255, 0.4)",
        },
        cyber: {
          blue: "#0080ff",
          cyan: "#00d2ff",
          electric: "#38bdf8",
          neon: "#00f0ff",
          teal: "#00e5ff",
          emerald: "#00f59b",
          purple: "#8b5cf6",
          surface: "#0f1623",
          bg: "#06090f",
          border: "#1e293b",
          accent: "#00d2ff",
          "text-primary": "#f8fafc",
          "text-secondary": "#94a3b8",
          "text-muted": "#64748b",
        },
        severity: {
          critical: "#ff3366",
          high: "#ff9900",
          medium: "#ffcc00",
          low: "#00a8ff",
          info: "#64748b",
        },
      },
      fontFamily: {
        sans: ["Inter", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["JetBrains Mono", "Fira Code", "ui-monospace", "monospace"],
      },
      boxShadow: {
        glow: "0 0 25px -4px rgba(0, 210, 255, 0.45)",
        "glow-lg": "0 0 45px -4px rgba(0, 210, 255, 0.6)",
        "glow-blue": "0 0 30px -4px rgba(0, 128, 255, 0.55)",
        "glow-emerald": "0 0 25px -4px rgba(0, 245, 155, 0.45)",
        "glow-danger": "0 0 25px -4px rgba(255, 51, 102, 0.45)",
        "glow-warning": "0 0 25px -4px rgba(255, 153, 0, 0.45)",
        glass: "0 8px 32px 0 rgba(0, 0, 0, 0.6)",
      },
      backgroundImage: {
        "gradient-radial": "radial-gradient(var(--tw-gradient-stops))",
        "shield-gradient": "linear-gradient(135deg, #0080ff 0%, #00d2ff 50%, #ffffff 100%)",
        "mesh-dark": "radial-gradient(circle at 50% 0%, rgba(0, 210, 255, 0.08) 0%, rgba(6, 9, 15, 0) 75%)",
      },
      keyframes: {
        "glow-pulse": {
          "0%, 100%": { opacity: "1", filter: "drop-shadow(0 0 15px rgba(0, 210, 255, 0.6))" },
          "50%": { opacity: "0.7", filter: "drop-shadow(0 0 5px rgba(0, 210, 255, 0.3))" },
        },
        "shield-float": {
          "0%, 100%": { transform: "translateY(0px)" },
          "50%": { transform: "translateY(-4px)" },
        },
        "scan-line": {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(1000%)" },
        },
        "fade-in-up": {
          "0%": { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        shimmer: {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" },
        },
      },
      animation: {
        "glow-pulse": "glow-pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "shield-float": "shield-float 4s ease-in-out infinite",
        "scan-line": "scan-line 6s linear infinite",
        "fade-in-up": "fade-in-up 0.35s ease-out forwards",
        shimmer: "shimmer 2.2s infinite linear",
      },
    },
  },
  plugins: [],
};

export default config;
