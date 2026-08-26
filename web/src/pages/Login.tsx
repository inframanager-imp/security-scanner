import { useState, type FormEvent } from 'react';
import { Navigate } from 'react-router-dom';
import { Mail, Lock, Eye, EyeOff, ShieldCheck, ArrowRight, AlertCircle, Loader2 } from 'lucide-react';
import { AuthLayout } from '../components/layout/AuthLayout';
import { useAuth } from '../hooks/useAuth';
import { ApiRequestError } from '../api/client';

export function Login() {
  const { isAuthenticated, login } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(true);
  const [loading, setLoading] = useState(false);
  const [isClicked, setIsClicked] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsClicked(true);
    setLoading(true);
    setTimeout(() => setIsClicked(false), 400);

    try {
      await login(email, password);
    } catch (err) {
      if (err instanceof ApiRequestError) {
        setError(
          err.status === 401
            ? 'Invalid authentication credentials. Access denied.'
            : `Login failed: ${err.message}`,
        );
      } else {
        setError('An unexpected system error occurred. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthLayout>
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-slate-900 font-sans tracking-wide">
          Sign In
        </h2>
        <p className="text-slate-500 text-xs mt-1">
          Enter your credentials to access the platform
        </p>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="mb-4 rounded-xl bg-red-50 border border-red-200 p-3 text-xs text-red-700 flex items-start gap-2 shadow-sm animate-fadeIn">
          <AlertCircle size={15} className="text-red-500 shrink-0 mt-0.5" />
          <div className="leading-relaxed">{error}</div>
        </div>
      )}

      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        {/* Email Field */}
        <div className="flex flex-col gap-1.5">
          <label className="text-xs font-semibold text-slate-700 tracking-wide">
            Email address
          </label>
          <div className="relative">
            <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3.5 text-slate-400">
              <Mail size={16} />
            </div>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="admin@example.com"
              required
              autoComplete="email"
              autoFocus
              className="w-full rounded-xl border border-slate-300 bg-slate-50/80 text-sm text-slate-900 placeholder-slate-400 pl-10 pr-3 py-2.5 transition-all outline-none focus:bg-white focus:border-blue-600 focus:ring-2 focus:ring-blue-600/20"
            />
          </div>
        </div>

        {/* Password Field */}
        <div className="flex flex-col gap-1.5">
          <div className="flex items-center justify-between">
            <label className="text-xs font-semibold text-slate-700 tracking-wide">
              Password
            </label>
            <a
              href="#forgot"
              onClick={(e) => {
                e.preventDefault();
                alert('For password resets, please contact your TrueTec System Administrator.');
              }}
              className="text-[11px] font-medium text-blue-600 hover:text-blue-700 transition-colors"
            >
              Forgot Password?
            </a>
          </div>
          <div className="relative">
            <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3.5 text-slate-400">
              <Lock size={16} />
            </div>
            <input
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              required
              autoComplete="current-password"
              className="w-full rounded-xl border border-slate-300 bg-slate-50/80 text-sm text-slate-900 placeholder-slate-400 pl-10 pr-10 py-2.5 transition-all outline-none focus:bg-white focus:border-blue-600 focus:ring-2 focus:ring-blue-600/20 font-mono"
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute inset-y-0 right-0 flex items-center pr-3.5 text-slate-400 hover:text-blue-600 hover:scale-110 active:scale-95 transition-all cursor-pointer"
              title={showPassword ? 'Hide password' : 'Show password'}
            >
              {showPassword ? (
                <EyeOff size={18} className="text-slate-400 hover:text-blue-600 transition-colors" />
              ) : (
                <Eye size={18} className="text-slate-400 hover:text-blue-600 transition-colors" />
              )}
            </button>
          </div>
        </div>

        {/* Remember Session Row */}
        <div className="flex items-center justify-between pt-0.5">
          <label className="flex items-center gap-2 cursor-pointer text-xs text-slate-600 hover:text-slate-900 transition-colors">
            <input
              type="checkbox"
              checked={rememberMe}
              onChange={(e) => setRememberMe(e.target.checked)}
              className="rounded bg-white border-slate-300 text-blue-600 focus:ring-blue-500 w-3.5 h-3.5"
            />
            <span>Remember me</span>
          </label>
        </div>

        {/* Light Theme Primary Submit Button */}
        <button
          type="submit"
          disabled={loading}
          className={`mt-2 w-full relative overflow-hidden inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-blue-600 via-cyan-600 to-blue-600 bg-[size:200%_auto] hover:bg-right text-white font-semibold py-2.5 px-4 text-sm shadow-md shadow-blue-500/20 active:scale-[0.97] transition-all duration-300 disabled:opacity-85 disabled:cursor-not-allowed cursor-pointer ${
            isClicked ? 'animate-btn-press ring-4 ring-blue-500/30' : ''
          }`}
        >
          {/* Animated laser shimmer beam overlay when loading */}
          {loading && (
            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent animate-btn-shimmer pointer-events-none" />
          )}

          {loading ? (
            <div className="flex items-center gap-2 z-10">
              <Loader2 size={18} className="animate-spin text-white" />
              <span className="tracking-wide">Signing In...</span>
            </div>
          ) : (
            <div className="flex items-center justify-center gap-2 z-10 group">
              <ShieldCheck size={17} className="transition-transform group-hover:scale-110" />
              <span>Sign In</span>
              <ArrowRight size={15} className="ml-0.5 opacity-80 group-hover:translate-x-1 transition-transform" />
            </div>
          )}
        </button>
      </form>
    </AuthLayout>
  );
}
