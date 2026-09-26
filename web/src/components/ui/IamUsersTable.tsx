import { useState, Fragment } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  ChevronDown,
  ChevronRight,
  ShieldAlert,
  ShieldCheck,
  KeyRound,
  Users,
  FileText,
  UserCheck,
  AlertCircle,
} from 'lucide-react';
import { iamUsersApi, type IamUserRow } from '../../api/iamUsers';
import { Card } from './Card';

interface IamUsersTableProps {
  accountId: string;
}

function formatAge(days: number | null): string {
  if (days === null) return '—';
  if (days === 0) return 'today';
  return `${days}d ago`;
}

function StatBadge({ ok, okLabel, badLabel }: { ok: boolean; okLabel: string; badLabel: string }) {
  return ok ? (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-xs font-bold bg-emerald-50 text-emerald-700 border border-emerald-200/80 shadow-2xs">
      <ShieldCheck size={13} className="text-emerald-500" />
      <span>{okLabel}</span>
    </span>
  ) : (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-xs font-bold bg-red-50 text-red-700 border border-red-200/80 shadow-2xs">
      <ShieldAlert size={13} className="text-red-500" />
      <span>{badLabel}</span>
    </span>
  );
}

function PolicyChip({ label, isAdmin }: { label: string; isAdmin: boolean }) {
  return (
    <span
      className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-semibold shadow-2xs transition-all ${
        isAdmin
          ? 'bg-red-50 text-red-700 border border-red-200/90'
          : 'bg-white text-gray-700 border border-gray-200/90'
      }`}
    >
      {isAdmin && <ShieldAlert size={12} className="text-red-500 shrink-0" />}
      <span>{label}</span>
      {isAdmin && (
        <span className="text-[10px] font-bold text-red-600 uppercase tracking-tight ml-0.5">
          (full admin)
        </span>
      )}
    </span>
  );
}

function UserDetailRow({ user }: { user: IamUserRow }) {
  return (
    <tr>
      <td colSpan={7} className="p-0 bg-slate-50/70 border-b border-gray-200">
        <div className="p-5 grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Groups Card */}
          <div className="bg-white rounded-xl border border-gray-200/90 p-4 space-y-2.5 shadow-2xs">
            <h4 className="text-xs font-extrabold text-gray-900 uppercase tracking-wider flex items-center gap-1.5 border-b border-gray-100 pb-2">
              <Users size={14} className="text-blue-600" />
              <span>Groups</span>
            </h4>
            {user.groups.length === 0 ? (
              <p className="text-xs text-gray-400 font-medium italic">No group memberships.</p>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {user.groups.map((g) => (
                  <PolicyChip key={g} label={g} isAdmin={false} />
                ))}
              </div>
            )}
          </div>

          {/* Policies Card */}
          <div className="bg-white rounded-xl border border-gray-200/90 p-4 space-y-2.5 shadow-2xs">
            <h4 className="text-xs font-extrabold text-gray-900 uppercase tracking-wider flex items-center gap-1.5 border-b border-gray-100 pb-2">
              <FileText size={14} className="text-blue-600" />
              <span>Policies (direct + via groups)</span>
            </h4>
            {user.directPolicies.length === 0 && user.groupPolicies.length === 0 ? (
              <p className="text-xs text-gray-400 font-medium italic">No attached policies.</p>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {user.directPolicies.map((p, i) => (
                  <PolicyChip key={`d-${i}`} label={p.name} isAdmin={p.isAdminEquivalent} />
                ))}
                {user.groupPolicies.map((p, i) => (
                  <PolicyChip
                    key={`g-${i}`}
                    label={`${p.policyName} (via ${p.groupName})`}
                    isAdmin={p.isAdminEquivalent}
                  />
                ))}
              </div>
            )}
          </div>

          {/* Assumable Roles Card */}
          <div className="bg-white rounded-xl border border-gray-200/90 p-4 space-y-2.5 shadow-2xs">
            <h4 className="text-xs font-extrabold text-gray-900 uppercase tracking-wider flex items-center gap-1.5 border-b border-gray-100 pb-2">
              <UserCheck size={14} className="text-blue-600" />
              <span>Assumable Roles</span>
            </h4>
            {user.assumableRoles.length === 0 ? (
              <p className="text-xs text-gray-400 font-medium italic">No roles this user can assume.</p>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {user.assumableRoles.map((r, i) => (
                  <PolicyChip
                    key={i}
                    label={`${r.roleName}${r.assumableBy === 'wildcard' ? ' (wildcard)' : ''}`}
                    isAdmin={r.isAdminEquivalent}
                  />
                ))}
              </div>
            )}
          </div>
        </div>
      </td>
    </tr>
  );
}

/** Dedicated IAM Users table: effective permissions, assumable roles, and access hygiene per user. */
export function IamUsersTable({ accountId }: IamUsersTableProps) {
  const [expandedUser, setExpandedUser] = useState<string | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ['iam-users', accountId],
    queryFn: () => iamUsersApi.list(accountId),
    enabled: !!accountId,
  });

  const users = data?.data ?? [];
  const openEndedCount = users.filter((u) => u.hasOpenEndedAccess).length;
  const hygieneIssueCount = users.filter((u) => u.mfaMissing || u.passwordStale || u.keyStale).length;

  return (
    <Card padding={false}>
      <div className="px-5 py-4 border-b border-gray-200 flex items-center justify-between flex-wrap gap-3 bg-white">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-blue-50 border border-blue-200/80 text-blue-600 shadow-2xs">
            <KeyRound size={18} />
          </div>
          <div>
            <h3 className="text-base font-extrabold text-gray-900 tracking-tight" style={{ fontFamily: 'var(--font-heading)' }}>
              IAM Users
            </h3>
            <p className="text-xs text-gray-500 font-medium mt-0.5">
              Effective permissions, assumable roles, and access hygiene per user.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs">
          {openEndedCount > 0 && (
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg bg-red-50 text-red-700 border border-red-200/90 font-bold shadow-2xs">
              <ShieldAlert size={13} className="text-red-500" />
              {openEndedCount} Open-ended
            </span>
          )}
          {hygieneIssueCount > 0 && (
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg bg-amber-50 text-amber-800 border border-amber-200/90 font-bold shadow-2xs">
              <AlertCircle size={13} className="text-amber-500" />
              {hygieneIssueCount} Hygiene Issues
            </span>
          )}
        </div>
      </div>

      {isLoading ? (
        <div className="p-6 space-y-3">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-10 bg-gray-100/80 rounded-lg animate-pulse" />
          ))}
        </div>
      ) : users.length === 0 ? (
        <div className="p-8 text-center text-xs text-gray-400 font-medium">
          No IAM users found for this account's latest scan.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-slate-50/80 border-b border-gray-200/80">
              <tr>
                <th className="w-10 px-3 py-3" />
                <th className="px-4 py-3 text-left text-[11px] font-bold text-gray-500 uppercase tracking-wider">
                  User
                </th>
                <th className="px-4 py-3 text-left text-[11px] font-bold text-gray-500 uppercase tracking-wider">
                  Access Level
                </th>
                <th className="px-4 py-3 text-left text-[11px] font-bold text-gray-500 uppercase tracking-wider">
                  MFA
                </th>
                <th className="px-4 py-3 text-left text-[11px] font-bold text-gray-500 uppercase tracking-wider">
                  Password Changed
                </th>
                <th className="px-4 py-3 text-left text-[11px] font-bold text-gray-500 uppercase tracking-wider">
                  Access Key Last Used
                </th>
                <th className="px-4 py-3 text-left text-[11px] font-bold text-gray-500 uppercase tracking-wider">
                  Groups / Roles
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {users.map((user) => {
                const isExpanded = expandedUser === user.userName;
                return (
                  <Fragment key={user.userName}>
                    <tr
                      className={`cursor-pointer transition-colors ${
                        user.hasOpenEndedAccess
                          ? 'bg-red-50/40 hover:bg-red-50/70'
                          : isExpanded
                          ? 'bg-slate-50'
                          : 'hover:bg-slate-50/70'
                      }`}
                      onClick={() => setExpandedUser(isExpanded ? null : user.userName)}
                    >
                      <td className="px-3 py-3.5 text-gray-400 text-center">
                        <div className="p-1 rounded-md text-gray-400 hover:text-gray-600 transition-colors">
                          {isExpanded ? (
                            <ChevronDown size={15} className="text-blue-600" />
                          ) : (
                            <ChevronRight size={15} />
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3.5 font-bold text-gray-900 text-sm">
                        {user.userName}
                      </td>
                      <td className="px-4 py-3.5">
                        {user.hasOpenEndedAccess ? (
                          <span className="inline-flex items-center gap-1.5 text-xs font-bold text-red-700 bg-red-50 border border-red-200/90 px-2.5 py-0.5 rounded-md shadow-2xs">
                            <ShieldAlert size={13} className="text-red-500" /> Open-ended (admin)
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-xs font-semibold text-gray-600 bg-gray-100 border border-gray-200 px-2.5 py-0.5 rounded-md">
                            Scoped
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3.5">
                        <StatBadge ok={user.mfaEnabled} okLabel="Enabled" badLabel="Not enabled" />
                      </td>
                      <td className="px-4 py-3.5">
                        {!user.passwordEnabled ? (
                          <span className="text-xs text-gray-400 font-medium">No console access</span>
                        ) : (
                          <span
                            className={`text-xs font-medium ${
                              user.passwordStale ? 'text-red-600 font-bold' : 'text-gray-700'
                            }`}
                          >
                            {formatAge(user.passwordAgeDays)}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3.5">
                        {user.accessKeysActive === 0 ? (
                          <span className="text-xs text-gray-400 font-medium">No active keys</span>
                        ) : user.hasNeverUsedActiveKey ? (
                          <span className="text-xs text-red-600 font-bold bg-red-50 border border-red-200 px-2 py-0.5 rounded-md">
                            Never used
                          </span>
                        ) : (
                          <span
                            className={`text-xs font-medium ${
                              user.keyStale ? 'text-red-600 font-bold' : 'text-gray-700'
                            }`}
                          >
                            {formatAge(user.accessKeyAgeDays)}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3.5 text-xs font-medium text-gray-600">
                        {user.groups.length} group{user.groups.length === 1 ? '' : 's'} · {user.assumableRoles.length} role{user.assumableRoles.length === 1 ? '' : 's'}
                      </td>
                    </tr>
                    {isExpanded && <UserDetailRow user={user} />}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
