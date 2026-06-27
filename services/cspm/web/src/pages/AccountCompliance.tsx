import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, CheckCircle2, XCircle, MinusCircle, ChevronDown, ChevronRight, FlaskConical, ShieldCheck } from 'lucide-react';
import { useState } from 'react';
import { complianceApi, type FrameworkScore, type ControlResult, type FrameworkId, type ComplianceEvidence } from '../api/compliance';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';

const FRAMEWORK_COLORS: Record<FrameworkId, { ring: string; bar: string; header: string; pill: string }> = {
  PCI_DSS:    { ring: 'ring-blue-200',   bar: 'bg-blue-500',    header: 'bg-blue-600',    pill: 'bg-blue-50 text-blue-700'       },
  SOC2:       { ring: 'ring-violet-200', bar: 'bg-violet-500',  header: 'bg-violet-600',  pill: 'bg-violet-50 text-violet-700'   },
  ISO27001:   { ring: 'ring-emerald-200',bar: 'bg-emerald-500', header: 'bg-emerald-600', pill: 'bg-emerald-50 text-emerald-700' },
  HIPAA:      { ring: 'ring-orange-200', bar: 'bg-orange-500',  header: 'bg-orange-600',  pill: 'bg-orange-50 text-orange-700'   },
  CIS_AWS:    { ring: 'ring-cyan-200',   bar: 'bg-cyan-500',    header: 'bg-cyan-600',    pill: 'bg-cyan-50 text-cyan-700'       },
  NIST_800_53:{ ring: 'ring-slate-200',  bar: 'bg-slate-600',   header: 'bg-slate-700',   pill: 'bg-slate-50 text-slate-700'     },
  GDPR:       { ring: 'ring-purple-200', bar: 'bg-purple-500',  header: 'bg-purple-600',  pill: 'bg-purple-50 text-purple-700'   },
  FEDRAMP:    { ring: 'ring-rose-200',   bar: 'bg-rose-500',    header: 'bg-rose-600',    pill: 'bg-rose-50 text-rose-700'       },
};

function scoreColor(score: number) {
  if (score >= 80) return 'text-emerald-600';
  if (score >= 60) return 'text-yellow-500';
  return 'text-red-500';
}

function ScoreGauge({ score, frameworkId }: { score: number; frameworkId: FrameworkId }) {
  const c = FRAMEWORK_COLORS[frameworkId];
  return (
    <div className="flex flex-col items-center">
      <span className={`text-4xl font-bold tabular-nums ${scoreColor(score)}`}>{score}%</span>
      <div className="mt-2 w-24 h-2 bg-gray-100 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full ${c.bar}`}
          style={{ width: `${score}%` }}
        />
      </div>
    </div>
  );
}

function EvidenceBadge({ status }: { status: string }) {
  if (status === 'COMPLIANT')
    return <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs font-medium bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200"><ShieldCheck size={10} />Evidence: Compliant</span>;
  if (status === 'NON_COMPLIANT')
    return <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs font-medium bg-red-50 text-red-700 ring-1 ring-red-200"><ShieldCheck size={10} />Evidence: Non-Compliant</span>;
  return <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs font-medium bg-yellow-50 text-yellow-700 ring-1 ring-yellow-200"><ShieldCheck size={10} />Evidence: Insufficient</span>;
}

function ControlRow({
  ctrl, frameworkId, accountId, provider,
}: {
  ctrl: ControlResult;
  frameworkId: FrameworkId;
  accountId?: string;
  provider?: string;
}) {
  const [open, setOpen] = useState(false);

  const { data: evidenceList } = useQuery({
    queryKey: ['evidence', frameworkId, ctrl.id, accountId],
    queryFn: () => complianceApi.getEvidence(frameworkId, ctrl.id, provider, accountId),
    enabled: open && !!accountId,
  });

  const latestEvidence = evidenceList?.[0] as ComplianceEvidence | undefined;

  return (
    <div className="border border-gray-100 rounded-lg overflow-hidden">
      <button
        className="w-full flex items-start gap-3 px-4 py-3 text-left hover:bg-gray-50 transition-colors"
        onClick={() => setOpen((v) => !v)}
      >
        {ctrl.status === 'PASS' ? (
          <CheckCircle2 size={16} className="text-emerald-500 mt-0.5 shrink-0" />
        ) : ctrl.status === 'FAIL' ? (
          <XCircle size={16} className="text-red-500 mt-0.5 shrink-0" />
        ) : (
          <MinusCircle size={16} className="text-gray-300 mt-0.5 shrink-0" />
        )}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-mono text-gray-400">{ctrl.id}</span>
            <span className="text-sm font-medium text-gray-800">{ctrl.name}</span>
            {ctrl.status === 'FAIL' && (
              <span className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-red-50 text-red-700 ring-1 ring-red-200">
                {ctrl.failingFindings} finding{ctrl.failingFindings !== 1 ? 's' : ''}
              </span>
            )}
            {ctrl.status === 'NOT_EVALUATED' && (
              <span className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-gray-50 text-gray-400 ring-1 ring-gray-200">
                not evaluated
              </span>
            )}
            {latestEvidence && <EvidenceBadge status={latestEvidence.status} />}
          </div>
        </div>
        {open ? (
          <ChevronDown size={14} className="text-gray-400 shrink-0 mt-0.5" />
        ) : (
          <ChevronRight size={14} className="text-gray-400 shrink-0 mt-0.5" />
        )}
      </button>

      {open && (
        <div className="px-4 pb-4 pt-1 border-t border-gray-100 bg-gray-50/60 space-y-3">
          <p className="text-xs text-gray-600">{ctrl.description}</p>

          {/* Evidence panel */}
          {latestEvidence && (
            <div className="rounded-md border border-gray-200 bg-white p-3 space-y-1.5">
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Latest Evidence</p>
              <div className="flex items-center gap-2">
                <EvidenceBadge status={latestEvidence.status} />
                <span className="text-xs text-gray-400">
                  {latestEvidence.evidenceType === 'MANUAL' ? 'Manual' : 'Auto-collected'} ·{' '}
                  {new Date(latestEvidence.collectedAt).toLocaleDateString()}
                  {latestEvidence.expiresAt && ` · expires ${new Date(latestEvidence.expiresAt).toLocaleDateString()}`}
                </span>
              </div>
              <p className="text-xs text-gray-600">{latestEvidence.summary}</p>
            </div>
          )}

          <div>
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1.5">
              Mapped Findings
            </p>
            <div className="flex flex-wrap gap-1.5">
              {ctrl.findingTitles.length === 0 ? (
                <span className="text-xs text-gray-400 italic">No findings mapped — cannot auto-evaluate</span>
              ) : (
                ctrl.findingTitles.map((title) => (
                  <span
                    key={title}
                    className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-white ring-1 ring-gray-200 text-gray-700"
                  >
                    {title}
                  </span>
                ))
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function FrameworkCard({
  fw, accountId, provider,
}: {
  fw: FrameworkScore;
  accountId?: string;
  provider: 'AWS' | 'AZURE' | 'GCP';
}) {
  const c = FRAMEWORK_COLORS[fw.frameworkId];
  const failControls = fw.controls.filter((c) => c.status === 'FAIL');
  const passControls = fw.controls.filter((c) => c.status === 'PASS');
  const naControls   = fw.controls.filter((c) => c.status === 'NOT_EVALUATED');
  const qc = useQueryClient();

  const collectMutation = useMutation({
    mutationFn: () => complianceApi.collectEvidence(accountId!, provider, fw.frameworkId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['evidence'] }),
  });

  return (
    <Card className={`overflow-hidden ring-1 ${c.ring}`}>
      {/* Header */}
      <div className={`px-5 py-4 flex items-center justify-between ${c.header}`}>
        <div>
          <p className="text-white text-xs font-medium opacity-80">{fw.frameworkName}</p>
          <p className="text-white text-lg font-bold">{fw.shortName}</p>
        </div>
        <div className="flex items-center gap-3">
          <ScoreGauge score={fw.score} frameworkId={fw.frameworkId} />
          {accountId && (
            <button
              onClick={() => collectMutation.mutate()}
              disabled={collectMutation.isPending}
              title="Auto-collect evidence for this framework"
              className="flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-white/20 text-white hover:bg-white/30 transition-colors disabled:opacity-50"
            >
              <FlaskConical size={12} />
              {collectMutation.isPending ? 'Collecting…' : 'Collect Evidence'}
            </button>
          )}
        </div>
      </div>

      {/* Stats strip */}
      <div className="px-5 py-3 bg-white border-b border-gray-100 flex gap-6 text-xs">
        <span>
          <strong className="text-emerald-600">{fw.passingControls}</strong>
          <span className="text-gray-500"> passing</span>
        </span>
        <span>
          <strong className="text-red-500">{fw.failingControls}</strong>
          <span className="text-gray-500"> failing</span>
        </span>
        {fw.notEvaluatedControls > 0 && (
          <span>
            <strong className="text-gray-400">{fw.notEvaluatedControls}</strong>
            <span className="text-gray-400"> not evaluated</span>
          </span>
        )}
        <span>
          <strong className="text-gray-700">{fw.totalControls}</strong>
          <span className="text-gray-500"> total</span>
        </span>
        {collectMutation.isSuccess && (
          <span className="text-emerald-600 font-medium">
            Evidence collected ✓
          </span>
        )}
      </div>

      {/* Controls list */}
      <div className="p-4 space-y-2">
        {failControls.length > 0 && (
          <p className="text-xs font-semibold text-red-500 uppercase tracking-wide mb-1">
            Failing Controls
          </p>
        )}
        {failControls.map((ctrl) => (
          <ControlRow key={ctrl.id} ctrl={ctrl} frameworkId={fw.frameworkId} accountId={accountId} provider={provider} />
        ))}

        {passControls.length > 0 && failControls.length > 0 && (
          <p className="text-xs font-semibold text-emerald-600 uppercase tracking-wide mt-3 mb-1">
            Passing Controls
          </p>
        )}
        {passControls.map((ctrl) => (
          <ControlRow key={ctrl.id} ctrl={ctrl} frameworkId={fw.frameworkId} accountId={accountId} provider={provider} />
        ))}

        {naControls.length > 0 && (
          <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mt-3 mb-1">
            Not Evaluated
          </p>
        )}
        {naControls.map((ctrl) => (
          <ControlRow key={ctrl.id} ctrl={ctrl} frameworkId={fw.frameworkId} accountId={accountId} provider={provider} />
        ))}
      </div>
    </Card>
  );
}

export function AccountCompliance() {
  const { accountId, provider: providerParam } = useParams<{ accountId: string; provider?: string }>();
  const navigate = useNavigate();
  const provider = (providerParam?.toUpperCase() as 'AWS' | 'AZURE' | 'GCP') ?? 'AWS';

  const { data: frameworks = [], isLoading } = useQuery({
    queryKey: ['compliance', accountId],
    queryFn: () => complianceApi.getAccountScores(accountId!),
    enabled: !!accountId,
  });

  const overallScore =
    frameworks.length > 0
      ? Math.round(frameworks.reduce((s, f) => s + f.score, 0) / frameworks.length)
      : null;

  return (
    <div className="space-y-6">
      {/* Back + title */}
      <div className="flex items-center gap-3">
        <Button variant="secondary" size="sm" onClick={() => navigate('/compliance')}>
          <ArrowLeft size={14} className="mr-1" />
          Back
        </Button>
        <div>
          <h2 className="text-lg font-semibold text-gray-900">Compliance Detail</h2>
          {overallScore !== null && (
            <p className={`text-sm font-medium ${scoreColor(overallScore)}`}>
              Overall average: {overallScore}%
            </p>
          )}
        </div>
      </div>

      {isLoading ? (
        <div className="py-16 text-center text-sm text-gray-400">Loading compliance data…</div>
      ) : frameworks.length === 0 ? (
        <Card className="py-16 text-center text-sm text-gray-400">
          No findings data available for this account.
        </Card>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          {frameworks.map((fw) => (
            <FrameworkCard key={fw.frameworkId} fw={fw} accountId={accountId} provider={provider} />
          ))}
        </div>
      )}
    </div>
  );
}
