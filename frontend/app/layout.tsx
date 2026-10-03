import type { Metadata } from "next";
import "./globals.css";
import { ToastContainer } from "@/components/ui/toast";
import { AuthInitializer } from "@/components/auth-initializer";

export const metadata: Metadata = {
  title: "CYBERSPLOI | Autonomous Cybersecurity Platform",
  description: "Enterprise offensive & defensive security mesh platform powered by AI.",
  icons: {
    icon: [
      { url: "/favicon.ico" },
      { url: "/icon.png", type: "image/png" },
      { url: "/shield-logo.png", type: "image/png" },
    ],
    apple: [
      { url: "/shield-logo-square.png" },
    ],
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-background text-slate-100 min-h-screen antialiased selection:bg-cyber-cyan selection:text-slate-950 font-sans">
        <AuthInitializer />
        {children}
        <ToastContainer />
      </body>
    </html>
  );
}
