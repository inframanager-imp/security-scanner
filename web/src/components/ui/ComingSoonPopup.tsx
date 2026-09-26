import type { ReactNode } from 'react';
import {
  Cloud,
  ShieldCheck,
  Lock,
  Code2,
  Sparkles,
} from 'lucide-react';

interface ComingSoonPopupProps {
  moduleName: string;
  enabled?: boolean;
  children: ReactNode;
}

/**
 * Reusable Light Theme Coming Soon Popup wrapper.
 * Features reduced font weight on "Coming Soon", subtle animated gradient text shimmer,
 * floating cloud doodles, and single-screen fit.
 */
export function ComingSoonPopup({ moduleName, enabled = true, children }: ComingSoonPopupProps) {
  if (!enabled) {
    return <>{children}</>;
  }

  return (
    <div className="relative min-h-[75vh] flex items-center justify-center p-4">
      {/* ── COMPACT LIGHT THEME "COMING SOON" POPUP CARD ── */}
      <div className="relative w-full max-w-md bg-white border border-slate-200/90 rounded-3xl shadow-[0_10px_40px_rgba(0,0,0,0.06)] p-6 sm:p-8 text-center z-10 my-auto overflow-hidden">
        
        {/* Top Accent Gradient Line */}
        <div className="absolute top-0 left-0 right-0 h-1.5 bg-gradient-to-r from-blue-600 via-cyan-500 to-indigo-600" />

        {/* Background Animated Radar doodle ring */}
        <div className="absolute inset-0 pointer-events-none overflow-hidden opacity-20">
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-64 h-64 border border-blue-400/40 rounded-full animate-spin-slow" />
        </div>

        {/* Floating Animated Cloud Security Doodles */}
        <div className="relative flex items-center justify-center gap-5 mb-5">
          {/* Doodle 1: Code */}
          <div className="p-3 rounded-2xl bg-sky-50 border border-sky-200 text-sky-600 shadow-sm animate-float-slow">
            <Code2 size={22} />
          </div>

          {/* Central Main Doodle: Cloud Security Shield */}
          <div className="relative">
            <div className="p-4.5 rounded-3xl bg-gradient-to-br from-blue-600 to-cyan-500 text-white shadow-lg shadow-blue-500/25 animate-bounce-slow">
              <Cloud size={40} className="stroke-[1.75]" />
            </div>
            {/* Floating Shield Badge */}
            <div className="absolute -bottom-1.5 -right-1.5 p-1.5 rounded-xl bg-emerald-500 text-white shadow-md border-2 border-white">
              <ShieldCheck size={16} />
            </div>
          </div>

          {/* Doodle 3: Zero-Trust Lock */}
          <div className="p-3 rounded-2xl bg-indigo-50 border border-indigo-200 text-indigo-600 shadow-sm animate-float-slow [animation-delay:1.5s]">
            <Lock size={22} />
          </div>
        </div>

        {/* Badge Tag with subtle glow animation */}
        <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full bg-blue-50/90 border border-blue-200/80 text-blue-700 text-xs font-semibold font-mono tracking-wider uppercase mb-3 shadow-xs animate-pulse">
          <Sparkles size={13} className="text-blue-600 animate-spin-slow" />
          <span>{moduleName}</span>
        </div>

        {/* Headline with reduced font weight (font-bold/600) & subtle text gradient shimmer animation */}
        <h2 className="text-2xl sm:text-3xl font-semibold bg-gradient-to-r from-slate-900 via-blue-800 to-slate-900 bg-clip-text text-transparent tracking-tight mb-5 animate-pulse">
          Coming Soon
        </h2>

        {/* Footer Status Pill */}
        <div className="flex items-center justify-center gap-2 text-[11px] font-mono text-slate-500 border-t border-slate-100 pt-4">
          <span className="flex h-2 w-2 relative">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-blue-500"></span>
          </span>
          <span className="font-semibold text-slate-700 tracking-wider">UNDER ACTIVE DEVELOPMENT</span>
        </div>

      </div>
    </div>
  );
}
