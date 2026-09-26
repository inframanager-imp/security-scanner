import type { ReactNode } from 'react';
import { Cloud, Lock, ShieldCheck } from 'lucide-react';

interface AuthLayoutProps {
  children: ReactNode;
}

export function AuthLayout({ children }: AuthLayoutProps) {
  return (
    <div className="h-screen w-screen relative flex items-center justify-center p-4 overflow-hidden select-none bg-slate-50 text-slate-900">
      {/* Light Theme Background SVG Image */}
      <div
        className="absolute inset-0 bg-cover bg-center bg-no-repeat transition-all duration-700 pointer-events-none opacity-95"
        style={{
          backgroundImage: `url('/img/cloud-security-bg.svg')`,
        }}
      />
      
      {/* Light Theme Ambient Grid Pattern */}
      <div className="absolute inset-0 bg-[radial-gradient(#cbd5e1_1px,transparent_1px)] [background-size:24px_24px] pointer-events-none opacity-40" />

      {/* Top-Right Light Security Telemetry Badges */}
      <div className="absolute top-4 right-4 sm:top-6 sm:right-8 z-20 hidden lg:flex items-center gap-2.5 text-[11px] font-mono text-slate-700">
        <div className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-white/90 border border-slate-200 text-blue-600 font-semibold backdrop-blur-md shadow-sm">
          <ShieldCheck size={13} />
          <span>TRUST VERIFIED</span>
        </div>
        <div className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-white/90 border border-slate-200 text-emerald-600 font-semibold backdrop-blur-md shadow-sm">
          <Lock size={12} />
          <span>ZERO-TRUST DEFENSE</span>
        </div>
        <div className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-white/90 border border-slate-200 text-sky-600 font-semibold backdrop-blur-md shadow-sm">
          <Cloud size={13} />
          <span>MULTI-CLOUD SHIELDED</span>
        </div>
      </div>

      {/* Bottom-Left Terminal Status Ticker */}
      <div className="absolute bottom-4 left-4 sm:bottom-6 sm:left-8 z-20 hidden md:flex items-center gap-2 text-[11px] font-mono text-slate-600">
        <span className="flex h-2.5 w-2.5 relative">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
          <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
        </span>
        <span className="text-emerald-700 font-bold uppercase">SYSTEM DEFENSE: ACTIVE</span>
      </div>

      {/* Bottom-Right Compliance Badge */}
      <div className="absolute bottom-4 right-4 sm:bottom-6 sm:right-8 z-20 hidden md:flex items-center gap-2 text-[11px] font-mono text-slate-600">
        <div className="px-3 py-1.5 rounded-xl bg-white/90 border border-slate-200 text-slate-700 font-semibold backdrop-blur-md shadow-sm">
          PRIVACY VAULT • SOC 2 TYPE II • ISO 27001
        </div>
      </div>

      {/* Main Centered Container: Large TrueTec Logo + Login Card */}
      <div className="w-full max-w-sm sm:max-w-md flex flex-col items-center z-10 my-auto">
        
        {/* Prominent Large Centered TrueTec Logo */}
        <div className="mb-6 flex justify-center">
          <img
            src="/img/logo.png"
            alt="TrueTec Logo"
            className="h-24 sm:h-28 lg:h-32 w-auto max-w-[420px] object-contain drop-shadow-md"
          />
        </div>

        {/* Login Form Card */}
        <div className="w-full relative">
          <div className="bg-white border border-slate-200/90 rounded-2xl shadow-2xl p-6 sm:p-8 relative overflow-hidden">
            {/* Top Accent Gradient Line */}
            <div className="absolute top-0 left-0 right-0 h-1.5 bg-gradient-to-r from-blue-600 via-cyan-500 to-blue-600" />
            
            {children}
          </div>
        </div>

      </div>
    </div>
  );
}
