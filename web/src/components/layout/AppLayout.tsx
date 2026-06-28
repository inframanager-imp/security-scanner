import { useEffect, useState, type ReactNode } from 'react';
import { NavLink, useLocation, Outlet } from 'react-router-dom';
import {
  Shield,
  LayoutDashboard,
  Layers,
  AlertTriangle,
  LogOut,
  ChevronRight,
  ScrollText,
  ShieldCheck,
  Box,
  ShieldAlert,
  FileText,
  GitCommit,
  Bell,
  SnowflakeIcon,
  GitCompareArrows,
  Link2,
  ClipboardList,
  Network,
  Users,
  Flame,
  Server,
  Database,
  Bug,
  Hexagon,
} from 'lucide-react';
import clsx from 'clsx';
import { useAuth } from '../../hooks/useAuth';

// ─── Nav types ────────────────────────────────────────────────────────────────

interface NavLeaf {
  to: string;
  icon: ReactNode;
  label: string;
}

interface NavSection {
  id: string;
  title: string;
  items: NavLeaf[];
}

// ─── Nav definition ───────────────────────────────────────────────────────────

// Standalone landing item (always visible, above the grouped sections).
const dashboardItem: NavLeaf = { to: '/dashboard', icon: <LayoutDashboard size={18} />, label: 'Dashboard' };

const navSections: NavSection[] = [
  {
    id: 'cloud',
    title: 'Cloud Security',
    items: [
      { to: '/cloud',          icon: <Layers size={16} />,          label: 'Cloud Subscriptions' },
      { to: '/compliance',     icon: <ShieldCheck size={16} />,     label: 'Compliance'          },
      { to: '/threats',        icon: <ShieldAlert size={16} />,     label: 'Threat Detection'    },
      { to: '/config-changes', icon: <GitCommit size={16} />,       label: 'Config Changes'      },
      { to: '/baselines',      icon: <GitCompareArrows size={16} />,label: 'Baseline & Drift'    },
      { to: '/posture-score',  icon: <Shield size={16} />,          label: 'Posture Score'       },
      { to: '/cloudtrail',     icon: <ScrollText size={16} />,      label: 'CloudTrail Logs'     },
      { to: '/azure-activity', icon: <FileText size={16} />,        label: 'Azure Activity Logs' },
      { to: '/containers',     icon: <Box size={16} />,             label: 'Container Security'  },
    ],
  },
  {
    id: 'appsec',
    title: 'Application Security',
    items: [
      { to: '/appsec/targets',  icon: <ClipboardList size={16} />,   label: 'Targets'             },
      { to: '/appsec/overview', icon: <LayoutDashboard size={16} />, label: 'App Posture'         },
      { to: '/appsec/web',      icon: <Server size={16} />,          label: 'Web Scan (DAST)'     },
      { to: '/appsec/api',      icon: <Network size={16} />,         label: 'API Security'        },
      { to: '/appsec/code',     icon: <FileText size={16} />,        label: 'Code Scan (SAST/SCA)'},
      { to: '/appsec/pentest',  icon: <Flame size={16} />,           label: 'Pentest (AI)'        },
      { to: '/appsec/ai-red',   icon: <Bug size={16} />,             label: 'AI Red Team'         },
    ],
  },
  {
    id: 'risk',
    title: 'Risk & Exposure',
    items: [
      { to: '/asset-graph',       icon: <Network size={16} />,      label: 'Asset Graph'             },
      { to: '/identity-graph',    icon: <Users size={16} />,        label: 'Identity & Attack Paths' },
      { to: '/prioritized-risks', icon: <Flame size={16} />,        label: 'Prioritized Risks'       },
      { to: '/workload-vulns',    icon: <Server size={16} />,       label: 'Workload Vulns'          },
      { to: '/data-security',     icon: <Database size={16} />,     label: 'Data Security'           },
      { to: '/iam-escalation',    icon: <ShieldAlert size={16} />,  label: 'IAM Escalation'          },
      { to: '/risk-register',     icon: <ClipboardList size={16} />,label: 'Risk Register'           },
    ],
  },
  {
    id: 'ops',
    title: 'Operations',
    items: [
      { to: '/reports',           icon: <AlertTriangle size={16} />,label: 'Reports'           },
      { to: '/integrations',      icon: <Link2 size={16} />,        label: 'Integrations'      },
      { to: '/alerts',            icon: <Bell size={16} />,         label: 'Alerts'            },
      { to: '/freeze-windows',    icon: <SnowflakeIcon size={16}/>, label: 'Freeze Windows'    },
      { to: '/scheduled-reports', icon: <FileText size={16} />,     label: 'Scheduled Reports' },
    ],
  },
];

function sectionForPath(pathname: string): string | null {
  for (const s of navSections) {
    if (s.items.some((i) => pathname === i.to || pathname.startsWith(i.to + '/'))) return s.id;
  }
  return null;
}

/** Section-aware breadcrumb: { section?, page } derived from the nav definition. */
function getBreadcrumb(pathname: string): { section: string | null; page: string } {
  for (const s of navSections) {
    for (const it of s.items) {
      if (pathname === it.to || pathname.startsWith(it.to + '/')) {
        return { section: s.title, page: it.label };
      }
    }
  }
  if (pathname === '/dashboard' || pathname === '/') return { section: null, page: 'Dashboard' };
  const secId = sectionForPath(pathname);
  const section = navSections.find((s) => s.id === secId)?.title ?? null;
  return { section, page: getPageTitle(pathname) };
}

// ─── Page title map ───────────────────────────────────────────────────────────

function getPageTitle(pathname: string): string {
  if (pathname === '/dashboard')            return 'Dashboard';
  if (pathname === '/cloud')                return 'Cloud Subscriptions';
  if (pathname.startsWith('/appsec'))       return 'Application Security (VA / PT)';
  if (pathname === '/reports')              return 'Security Reports';
  if (pathname.startsWith('/accounts/'))    return 'Account Detail';
  if (pathname.startsWith('/scans/'))       return 'Scan Detail';
  if (pathname.startsWith('/reports/'))     return 'Account Report';
  if (pathname === '/cloudtrail')           return 'CloudTrail Logs';
  if (pathname === '/compliance')           return 'Compliance';
  if (pathname.startsWith('/compliance/'))  return 'Account Compliance';
  if (pathname === '/containers')           return 'Container Security';
  if (pathname === '/threats')              return 'Threat Detection';
  if (pathname.startsWith('/azure/'))       return 'Azure Subscription';
  if (pathname === '/azure-activity')       return 'Azure Activity Logs';
  if (pathname === '/config-changes')       return 'Config Changes';
  if (pathname.startsWith('/config-changes/')) return 'Config Changes Report';
  if (pathname === '/baselines')            return 'Baseline & Drift Detection';
  if (pathname === '/posture-score')        return 'Risk Posture Score';
  if (pathname === '/asset-graph')          return 'Asset Graph';
  if (pathname === '/identity-graph')       return 'Identity & Attack Paths';
  if (pathname.startsWith('/attack-paths/')) return 'Attack Path Detail';
  if (pathname === '/prioritized-risks')    return 'Prioritized Risks';
  if (pathname === '/workload-vulns')       return 'Workload Vulnerabilities';
  if (pathname === '/data-security')        return 'Data Security';
  if (pathname === '/iam-escalation')       return 'IAM Privilege Escalation';
  if (pathname === '/risk-register')        return 'Risk Register';
  if (pathname === '/alerts')               return 'Alert Configuration';
  if (pathname === '/integrations')         return 'Integrations';
  if (pathname === '/freeze-windows')       return 'Freeze Windows';
  if (pathname === '/scheduled-reports')    return 'Scheduled Reports';
  return 'Cloud Scanner';
}

// ─── Nav leaf + collapsible section ─────────────────────────────────────────────

function NavLeaf({ item, end }: { item: NavLeaf; end?: boolean }) {
  return (
    <NavLink
      to={item.to}
      end={end}
      className={({ isActive }) =>
        clsx(
          'flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all duration-150',
          isActive
            ? 'bg-gradient-to-r from-[#1D4ED8] to-[#2563EB] text-white shadow-lg shadow-blue-900/40'
            : 'text-[#D8E6FF] hover:text-white hover:bg-white/5',
        )
      }
    >
      {item.icon}
      <span className="flex-1">{item.label}</span>
    </NavLink>
  );
}

function NavSectionRow({
  section, isOpen, onToggle,
}: { section: NavSection; isOpen: boolean; onToggle: () => void }) {
  return (
    <div>
      <button
        onClick={onToggle}
        className="flex items-center w-full px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-[#8EA6C8] hover:text-[#D8E6FF] transition-colors"
      >
        <span className="flex-1 text-left">{section.title}</span>
        <ChevronRight size={12} className={clsx('transition-transform duration-150 shrink-0', isOpen && 'rotate-90')} />
      </button>
      {isOpen && (
        <div className="space-y-0.5 mb-1">
          {section.items.map((it) => <NavLeaf key={it.to} item={it} />)}
        </div>
      )}
    </div>
  );
}

// ─── Layout ───────────────────────────────────────────────────────────────────

export function AppLayout() {
  const { user, logout } = useAuth();
  const location = useLocation();
  const crumb = getBreadcrumb(location.pathname);

  // Accordion: one section open at a time, auto-expands the active section on nav.
  const activeSection = sectionForPath(location.pathname);
  const [openId, setOpenId] = useState<string | null>(activeSection ?? 'cloud');
  useEffect(() => {
    if (activeSection) setOpenId(activeSection);
  }, [activeSection]);

  return (
    <div className="flex h-screen bg-gray-50 overflow-hidden">
      {/* Sidebar */}
      <aside className="sidebar-ocean relative flex flex-col w-[280px] shrink-0 text-white">
        {/* Realistic ocean wave photo, faded into the navy gradient */}
        <div className="sidebar-wave-img" />
        <div className="pointer-events-none absolute inset-x-0 bottom-0 z-0 h-64 bg-gradient-to-t from-[#031327]/80 via-[#072245]/25 to-transparent" />

        {/* Logo */}
        <div className="relative z-10 flex items-center gap-3 px-5 py-5 border-b border-white/10">
          <div className="flex items-center justify-center h-10 w-10 rounded-xl bg-gradient-to-br from-blue-500 to-blue-700 shadow-lg shadow-blue-900/50">
            <Hexagon size={20} className="text-white" />
          </div>
          <div>
            <span className="text-white font-bold text-lg leading-none">Cloud Scanner</span>
            <span className="block text-[#8EA6C8] text-xs mt-1">Security Platform</span>
          </div>
        </div>

        {/* Navigation */}
        <nav className="relative z-10 flex-1 px-3 py-4 space-y-0.5 overflow-y-auto no-scrollbar">
          <NavLeaf item={dashboardItem} end />
          <div className="my-2 border-t border-white/10" />
          {navSections.map((section) => (
            <NavSectionRow
              key={section.id}
              section={section}
              isOpen={openId === section.id}
              onToggle={() => setOpenId(openId === section.id ? null : section.id)}
            />
          ))}
        </nav>

        {/* Sign Out (profile detail moved to the top bar) */}
        <div className="relative z-10 px-3 py-4 border-t border-white/10">
          <button
            onClick={logout}
            className="flex w-full items-center gap-3 px-3 py-2 rounded-lg text-sm text-[#D8E6FF] hover:text-white hover:bg-white/5 transition-colors duration-150"
          >
            <LogOut size={16} />
            Sign Out
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <div className="flex flex-col flex-1 overflow-hidden">
        {/* Top Bar */}
        <header className="flex items-center gap-2 px-6 py-4 bg-white border-b border-gray-200 shrink-0">
          {crumb.section && (
            <div className="flex items-center gap-1 text-gray-400 text-sm">
              <span>{crumb.section}</span>
              <ChevronRight size={14} />
            </div>
          )}
          <h1 className="text-base font-semibold text-gray-900">{crumb.page}</h1>

          {/* Profile (top-right) */}
          <div className="ml-auto flex items-center gap-3">
            <div className="text-right leading-tight hidden sm:block">
              <p className="text-sm font-medium text-gray-900 truncate max-w-[200px]">{user?.email ?? 'User'}</p>
              <p className="text-xs text-gray-500">{user?.role ?? ''}</p>
            </div>
            <div className="h-9 w-9 rounded-full bg-gradient-to-br from-blue-500 to-blue-700 flex items-center justify-center text-white text-sm font-bold shrink-0 shadow-md shadow-blue-900/30">
              {user?.email?.[0]?.toUpperCase() ?? 'U'}
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 overflow-y-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
