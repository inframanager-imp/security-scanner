import type { ReactNode } from 'react';
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
} from 'lucide-react';
import clsx from 'clsx';
import { useAuth } from '../../hooks/useAuth';

// ─── Nav types ────────────────────────────────────────────────────────────────

interface NavItem {
  to: string;
  icon: ReactNode;
  label: string;
  children?: { to: string; icon: ReactNode; label: string }[];
}

// ─── Nav definition ───────────────────────────────────────────────────────────

const navItems: NavItem[] = [
  { to: '/dashboard',     icon: <LayoutDashboard size={18} />, label: 'Dashboard'          },
  { to: '/cloud',         icon: <Layers size={18} />,          label: 'Cloud Subscriptions'},
  { to: '/reports',       icon: <AlertTriangle size={18} />,   label: 'Reports'            },
  { to: '/cloudtrail',    icon: <ScrollText size={18} />,      label: 'CloudTrail Logs'    },
  { to: '/compliance',    icon: <ShieldCheck size={18} />,     label: 'Compliance'         },
  { to: '/containers',    icon: <Box size={18} />,             label: 'Container Security' },
  { to: '/threats',       icon: <ShieldAlert size={18} />,     label: 'Threat Detection'   },
  { to: '/azure-activity',icon: <FileText size={18} />,        label: 'Azure Activity Logs'},
  {
    to:    '/config-changes',
    icon:  <GitCommit size={18} />,
    label: 'Config Changes',
    children: [
      { to: '/baselines',    icon: <GitCompareArrows size={15} />, label: 'Baseline & Drift'    },
      { to: '/posture-score',icon: <Shield size={15} />,           label: 'Risk Posture Score'  },
    ],
  },
  { to: '/asset-graph',       icon: <Network size={18} />,       label: 'Asset Graph'         },
  { to: '/identity-graph',    icon: <Users size={18} />,         label: 'Identity & Attack Paths' },
  { to: '/prioritized-risks', icon: <Flame size={18} />,         label: 'Prioritized Risks'   },
  { to: '/workload-vulns',    icon: <Server size={18} />,        label: 'Workload Vulns'      },
  { to: '/data-security',     icon: <Database size={18} />,      label: 'Data Security'       },
  { to: '/iam-escalation',    icon: <ShieldAlert size={18} />,   label: 'IAM Escalation'     },
  { to: '/risk-register',     icon: <ClipboardList size={18} />, label: 'Risk Register'       },
  { to: '/alerts',            icon: <Bell size={18} />,        label: 'Alert Configuration' },
  { to: '/integrations',      icon: <Link2 size={18} />,       label: 'Integrations'        },
  { to: '/freeze-windows',    icon: <SnowflakeIcon size={18}/>, label: 'Freeze Windows'     },
  { to: '/scheduled-reports', icon: <FileText size={18} />,    label: 'Scheduled Reports'   },
];

// ─── Page title map ───────────────────────────────────────────────────────────

function getPageTitle(pathname: string): string {
  if (pathname === '/dashboard')            return 'Dashboard';
  if (pathname === '/cloud')                return 'Cloud Subscriptions';
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

// ─── Nav link + children ──────────────────────────────────────────────────────

function NavRow({ item, pathname }: { item: NavItem; pathname: string }) {
  const isChildActive = item.children?.some((c) => pathname.startsWith(c.to));
  const isSelfActive  = pathname === item.to || pathname.startsWith(item.to + '/');
  const showChildren  = !!(item.children && (isSelfActive || isChildActive));

  return (
    <div>
      <NavLink
        to={item.to}
        end={!!item.children}
        className={({ isActive }) =>
          clsx(
            'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors duration-150',
            (isActive || isChildActive)
              ? 'bg-blue-600 text-white'
              : 'text-gray-400 hover:text-white hover:bg-gray-800',
          )
        }
      >
        {item.icon}
        <span className="flex-1">{item.label}</span>
        {item.children && (
          <ChevronRight
            size={13}
            className={clsx(
              'transition-transform duration-150 shrink-0',
              showChildren ? 'rotate-90' : '',
            )}
          />
        )}
      </NavLink>

      {/* Children */}
      {item.children && showChildren && (
        <div className="ml-4 mt-0.5 space-y-0.5 border-l border-gray-700 pl-2">
          {item.children.map((child) => (
            <NavLink
              key={child.to}
              to={child.to}
              className={({ isActive }) =>
                clsx(
                  'flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium transition-colors duration-150',
                  isActive
                    ? 'bg-blue-500 text-white'
                    : 'text-gray-400 hover:text-white hover:bg-gray-800',
                )
              }
            >
              {child.icon}
              {child.label}
            </NavLink>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Layout ───────────────────────────────────────────────────────────────────

export function AppLayout() {
  const { user, logout } = useAuth();
  const location = useLocation();
  const pageTitle = getPageTitle(location.pathname);

  return (
    <div className="flex h-screen bg-gray-50 overflow-hidden">
      {/* Sidebar */}
      <aside className="flex flex-col w-64 bg-gray-900 shrink-0">
        {/* Logo */}
        <div className="flex items-center gap-3 px-5 py-5 border-b border-gray-800">
          <div className="flex items-center justify-center h-9 w-9 rounded-lg bg-blue-600">
            <Shield size={18} className="text-white" />
          </div>
          <div>
            <span className="text-white font-bold text-lg leading-none">Cloud Scanner</span>
            <span className="block text-gray-500 text-xs mt-0.5">Security Platform</span>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {navItems.map((item) => (
            <NavRow key={item.to} item={item} pathname={location.pathname} />
          ))}
        </nav>

        {/* User Section */}
        <div className="px-3 py-4 border-t border-gray-800">
          <div className="flex items-center gap-3 px-3 py-2 rounded-lg">
            <div className="h-8 w-8 rounded-full bg-blue-600 flex items-center justify-center text-white text-sm font-bold shrink-0">
              {user?.email?.[0]?.toUpperCase() ?? 'U'}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-white text-sm font-medium truncate">
                {user?.email ?? 'User'}
              </p>
              <p className="text-gray-500 text-xs">{user?.role ?? ''}</p>
            </div>
          </div>
          <button
            onClick={logout}
            className="mt-1 flex w-full items-center gap-3 px-3 py-2 rounded-lg text-sm text-gray-400 hover:text-white hover:bg-gray-800 transition-colors duration-150"
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
          <div className="flex items-center gap-1 text-gray-400 text-sm">
            <span>Cloud Scanner</span>
            <ChevronRight size={14} />
          </div>
          <h1 className="text-base font-semibold text-gray-900">{pageTitle}</h1>
        </header>

        {/* Page Content */}
        <main className="flex-1 overflow-y-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
