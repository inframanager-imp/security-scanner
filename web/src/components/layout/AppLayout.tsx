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
  Cloud,
  Code2,
  Activity,
  PanelLeftClose,
  PanelLeftOpen,
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
  icon: ReactNode;
  items: NavLeaf[];
}

// ─── Nav definition ───────────────────────────────────────────────────────────

// Standalone landing item (always visible, above the grouped sections).
const dashboardItem: NavLeaf = { to: '/dashboard', icon: <LayoutDashboard size={20} strokeWidth={2} />, label: 'Dashboard' };

const navSections: NavSection[] = [
  {
    id: 'cloud',
    title: 'Cloud Security',
    icon: <Cloud size={15} className="text-blue-400 shrink-0" />,
    items: [
      { to: '/cloud',          icon: <Layers size={16} />,          label: 'Cloud Subscriptions' },
      { to: '/compliance',     icon: <ShieldCheck size={16} />,     label: 'Compliance'          },
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
    icon: <Code2 size={15} className="text-indigo-400 shrink-0" />,
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
    icon: <ShieldAlert size={15} className="text-amber-400 shrink-0" />,
    items: [
      { to: '/asset-graph',       icon: <Network size={16} />,      label: 'Asset Graph'             },
      { to: '/identity-graph',    icon: <Users size={16} />,        label: 'Identity & Attack Paths' },
      { to: '/threats',           icon: <ShieldAlert size={16} />,  label: 'Threat Detection'        },
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
    icon: <Activity size={15} className="text-emerald-400 shrink-0" />,
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

// ─── Nav leaf + collapsible section ─────────────────────────────────────────────

function NavLeaf({
  item, end, isCollapsed,
}: { item: NavLeaf; end?: boolean; isCollapsed?: boolean }) {
  return (
    <NavLink
      to={item.to}
      end={end}
      title={isCollapsed ? item.label : undefined}
      className={({ isActive }) =>
        clsx(
          'cca-nav-item',
          isActive && 'active'
        )
      }
    >
      <span className="shrink-0 text-[#4b9cd3]">{item.icon}</span>
      {!isCollapsed && <span className="truncate">{item.label}</span>}
    </NavLink>
  );
}

function NavSectionRow({
  section, isOpen, onToggle, isCollapsed, hasActivePage,
}: { section: NavSection; isOpen: boolean; onToggle: () => void; isCollapsed?: boolean; hasActivePage?: boolean }) {
  return (
    <div
      className={clsx(
        'cca-nav-group my-1',
        isOpen && !isCollapsed && 'expanded',
        hasActivePage && 'has-active-page'
      )}
    >
      <div className="cca-card-header" onClick={onToggle}>
        <div className="cca-card-header-left">
          <span className="text-[#4b9cd3]">{section.icon}</span>
          <span className="cca-card-title">{section.title}</span>
        </div>
        <div className="cca-card-chevron">
          <ChevronRight size={14} className="text-[#0284C7]" />
        </div>
      </div>

      <div className="cca-card-body">
        {section.items.map((it) => <NavLeaf key={it.to} item={it} />)}
      </div>
    </div>
  );
}

// ─── Layout ───────────────────────────────────────────────────────────────────

export function AppLayout() {
  const { user, logout } = useAuth();
  const location = useLocation();
  const crumb = getBreadcrumb(location.pathname);
  const [isCollapsed, setIsCollapsed] = useState(true);

  // Accordion: one section open at a time, auto-expands the active section on nav.
  const activeSection = sectionForPath(location.pathname);
  const [openId, setOpenId] = useState<string | null>(activeSection ?? 'cloud');
  useEffect(() => {
    if (activeSection) setOpenId(activeSection);
  }, [activeSection]);

  return (
    <div className="flex h-screen bg-gray-50 overflow-hidden">
      {/* Sidebar */}
      <aside
        onMouseEnter={() => setIsCollapsed(false)}
        onMouseLeave={() => setIsCollapsed(true)}
        className={clsx(
          'sidebar-cca relative flex flex-col shrink-0 text-slate-800 border-r border-[#E1F0FA] transition-all duration-300 ease-in-out z-30',
          isCollapsed ? 'w-[68px] is-collapsed' : 'w-[245px]',
        )}
      >
        {/* Header & Logo */}
        <div className="relative z-10 flex items-center justify-between px-3.5 py-4 border-b border-[#E1F0FA]">
          <div className="flex items-center gap-3 overflow-hidden">
            <div className="flex items-center justify-center h-9 w-9 rounded-xl bg-gradient-to-tr from-blue-600 to-sky-400 text-white shrink-0">
              <Hexagon size={20} className="text-white fill-white/20" />
            </div>
            {!isCollapsed && (
              <div className="flex flex-col truncate">
                <span className="text-[14px] font-medium text-[#4b9cd3] leading-[1.2] -tracking-[0.01em] block truncate">Cloud Scanner</span>
                <span className="text-[14px] font-medium text-[#4b9cd3] leading-[1.2] -tracking-[0.01em] block truncate">Security Platform</span>
              </div>
            )}
          </div>
        </div>

        {/* Navigation */}
        <nav className="relative z-10 flex-1 px-2 py-2.5 space-y-1.5 overflow-y-auto no-scrollbar">
          {/* Dashboard Item */}
          <div className={clsx('cca-nav-group my-1', (location.pathname === '/dashboard' || location.pathname === '/') && 'has-active-page')}>
            <NavLink to="/dashboard" className="cca-card-header w-full">
              <div className="cca-card-header-left">
                <span className="text-[#4b9cd3]">{dashboardItem.icon}</span>
                <span className="cca-card-title">{dashboardItem.label}</span>
              </div>
            </NavLink>
          </div>

          {/* Domain Section Groups */}
          {navSections.map((section) => {
            const hasActivePage = activeSection === section.id;
            return (
              <NavSectionRow
                key={section.id}
                section={section}
                isOpen={openId === section.id}
                onToggle={() => setOpenId(openId === section.id ? null : section.id)}
                isCollapsed={isCollapsed}
                hasActivePage={hasActivePage}
              />
            );
          })}
        </nav>

        {/* User Profile & Sign Out Footer */}
        <div className="relative z-10 px-3 py-3 border-t border-[#E1F0FA] bg-[#F7FAFD]">
          {!isCollapsed ? (
            <div className="flex items-center justify-between gap-2 p-2 rounded-xl bg-white border border-[#E1F0FA]">
              <div className="flex items-center gap-2.5 overflow-hidden">
                <div className="h-8 w-8 rounded-lg bg-[#4b9cd3] flex items-center justify-center text-white text-xs font-bold shrink-0">
                  {user?.email?.[0]?.toUpperCase() ?? 'U'}
                </div>
                <div className="truncate leading-tight">
                  <p className="text-xs font-semibold text-slate-800 truncate max-w-[130px]">
                    {user?.email ?? 'User'}
                  </p>
                  <p className="text-[10px] font-semibold text-[#4b9cd3] uppercase tracking-wider truncate">
                    {user?.role ?? 'Admin'}
                  </p>
                </div>
              </div>
              <button
                onClick={logout}
                title="Sign Out"
                className="p-1.5 rounded-lg text-slate-400 hover:text-red-600 hover:bg-red-50 transition-colors shrink-0"
              >
                <LogOut size={16} />
              </button>
            </div>
          ) : (
            <div className="flex flex-col items-center gap-2 py-1">
              <div
                className="h-8 w-8 rounded-lg bg-[#4b9cd3] flex items-center justify-center text-white text-xs font-bold"
                title={user?.email ?? 'User'}
              >
                {user?.email?.[0]?.toUpperCase() ?? 'U'}
              </div>
              <button
                onClick={logout}
                title="Sign Out"
                className="p-1.5 rounded-lg text-slate-400 hover:text-red-600 hover:bg-red-50 transition-colors"
              >
                <LogOut size={16} />
              </button>
            </div>
          )}
        </div>
      </aside>

      {/* Main Content */}
      <div className="flex flex-col flex-1 overflow-hidden">
        {/* Top Bar */}
        <header className="flex items-center gap-2 px-6 py-4 bg-white border-b border-gray-200 shrink-0">
          {crumb.section && (
            <div className="flex items-center gap-1 text-gray-400 text-sm font-medium">
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

