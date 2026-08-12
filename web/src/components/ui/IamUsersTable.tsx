import { useState, Fragment } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ChevronDown, ChevronRight, ShieldAlert, ShieldCheck, KeyRound, Users } from 'lucide-react';
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
    <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-700">
      <ShieldCheck size={12} /> {okLabel}
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 text-xs font-medium text-red-600">
      <ShieldAlert size={12} /> {badLabel}
    </span>
  );
}

function PolicyChip({ label, isAdmin }: { label: string; isAdmin: boolean }) {
  return (
    <span
      className={`inline-block px-2 py-0.5 rounded text-[11px] font-medium mr-1 mb-1 ${
        isAdmin ? 'bg-red-100 text-red-700 ring-1 ring-red-300' : 'bg-gray-100 text-gray-600'
      }`}
    >
      {label}{isAdmin && ' (full admin)'}
    </span>
  );
}

function UserDetailRow({ user }: { user: IamUserRow }) {
  return (
    <tr>
      <td colSpan={7} className="px-6 py-4 bg-gray-50 border-b border-gray-200">
        <div className="grid grid-cols-3 gap-6 text-sm">
          <div>
            <h4 className="font-semibold text-gray-900 mb-2 flex items-center gap-1.5"><Users size={13} /> Groups</h4>
            {user.groups.length === 0 ? (
              <p className="text-xs text-gray-400">No group memberships.</p>
            ) : (
              <div>{user.groups.map(g => <PolicyChip key={g} label={g} isAdmin={false} />)}</div>
            )}
          </div>
          <div>
            <h4 className="font-semibold text-gray-900 mb-2">Policies (direct + via groups)</h4>
            {user.directPolicies.length === 0 && user.groupPolicies.length === 0 ? (
              <p className="text-xs text-gray-400">No attached policies.</p>
            ) : (
              <div>
                {user.directPolicies.map((p, i) => <PolicyChip key={`d-${i}`} label={p.name} isAdmin={p.isAdminEquivalent} />)}
                {user.groupPolicies.map((p, i) => (
                  <PolicyChip key={`g-${i}`} label={`${p.policyName} (via ${p.groupName})`} isAdmin={p.isAdminEquivalent} />
                ))}
              </div>
            )}
          </div>
          <div>
            <h4 className="font-semibold text-gray-900 mb-2">Assumable Roles</h4>
            {user.assumableRoles.length === 0 ? (
              <p className="text-xs text-gray-400">No roles this user can assume.</p>
            ) : (
              <div>
                {user.assumableRoles.map((r, i) => (
                  <PolicyChip
                    key={i}
                    label={`${r.roleName}${r.assumableBy === 'wildcard' ? ' (assumable by anyone)' : ''}`}
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
    queryFn:  () => iamUsersApi.list(accountId),
    enabled:  !!accountId,
  });

  const users = data?.data ?? [];
  const openEndedCount = users.filter(u => u.hasOpenEndedAccess).length;
  const hygieneIssueCount = users.filter(u => u.mfaMissing || u.passwordStale || u.keyStale).length;

  return (
    <Card padding={false}>
      <div className="px-4 py-3 border-b border-gray-200 flex items-center justify-between flex-wrap gap-2">
        <div>
          <h3 className="text-sm font-semibold text-gray-900 flex items-center gap-1.5">
            <KeyRound size={15} /> IAM Users
          </h3>
          <p className="text-xs text-gray-500 mt-0.5">
            Effective permissions, assumable roles, and access hygiene per user.
          </p>
        </div>
        <div className="flex items-center gap-3 text-xs">
          {openEndedCount > 0 && (
            <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full bg-red-50 text-red-700 border border-red-200 font-medium">
              {openEndedCount} open-ended
            </span>
          )}
          {hygieneIssueCount > 0 && (
            <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full bg-yellow-50 text-yellow-700 border border-yellow-200 font-medium">
              {hygieneIssueCount} with hygiene issues
            </span>
          )}
        </div>
      </div>

      {isLoading ? (
        <div className="p-6 space-y-3">
          {[...Array(3)].map((_, i) => <div key={i} className="h-8 bg-gray-100 rounded animate-pulse" />)}
        </div>
      ) : users.length === 0 ? (
        <div className="p-8 text-center text-sm text-gray-400">
          No IAM users found for this account's latest scan.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-100 bg-gray-50">
                <th className="w-8 px-2 py-3" />
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">User</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Access Level</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">MFA</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Password Changed</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Access Key Last Used</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Groups / Roles</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {users.map(user => {
                const isExpanded = expandedUser === user.userName;
                return (
                  <Fragment key={user.userName}>
                    <tr
                      className={`cursor-pointer transition-colors ${user.hasOpenEndedAccess ? 'bg-red-50/50 hover:bg-red-50' : 'hover:bg-gray-50'}`}
                      onClick={() => setExpandedUser(isExpanded ? null : user.userName)}
                    >
                      <td className="px-2 py-3 text-gray-400">
                        {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                      </td>
                      <td className="px-4 py-3 font-medium text-gray-900">{user.userName}</td>
                      <td className="px-4 py-3">
                        {user.hasOpenEndedAccess ? (
                          <span className="inline-flex items-center gap-1 text-xs font-semibold text-red-700 bg-red-100 px-2 py-0.5 rounded-full ring-1 ring-red-300">
                            <ShieldAlert size={12} /> Open-ended (admin)
                          </span>
                        ) : (
                          <span className="text-xs text-gray-500">Scoped</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <StatBadge ok={user.mfaEnabled} okLabel="Enabled" badLabel="Not enabled" />
                      </td>
                      <td className="px-4 py-3">
                        {!user.passwordEnabled ? (
                          <span className="text-xs text-gray-400">No console access</span>
                        ) : (
                          <span className={`text-xs ${user.passwordStale ? 'text-red-600 font-medium' : 'text-gray-600'}`}>
                            {formatAge(user.passwordAgeDays)}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        {user.accessKeysActive === 0 ? (
                          <span className="text-xs text-gray-400">No active keys</span>
                        ) : user.hasNeverUsedActiveKey ? (
                          <span className="text-xs text-red-600 font-medium">Never used</span>
                        ) : (
                          <span className={`text-xs ${user.keyStale ? 'text-red-600 font-medium' : 'text-gray-600'}`}>
                            {formatAge(user.accessKeyAgeDays)}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-xs text-gray-500">
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
