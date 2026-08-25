import { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { FileBarChart } from 'lucide-react';
import { reportsApi, type ReportProvider } from '../../api/reports';
import { Modal } from './Modal';
import { Button } from './Button';
import { MultiSelect } from './MultiSelect';

const AWS_FRAMEWORKS = [
  { value: '', label: 'All Frameworks (Full Report)' },
  { value: 'PCI_DSS', label: 'PCI DSS' },
  { value: 'SOC2', label: 'SOC 2' },
  { value: 'ISO27001', label: 'ISO 27001' },
  { value: 'HIPAA', label: 'HIPAA' },
  { value: 'CIS_AWS', label: 'CIS AWS Foundations' },
  { value: 'NIST_800_53', label: 'NIST 800-53' },
  { value: 'GDPR', label: 'GDPR' },
  { value: 'FEDRAMP', label: 'FedRAMP' },
];

const AZURE_FRAMEWORKS = [
  { value: '', label: 'All Frameworks (Full Report)' },
  { value: 'CIS_AZURE', label: 'CIS Microsoft Azure Foundations' },
  { value: 'NIST', label: 'NIST' },
  { value: 'ISO27001', label: 'ISO 27001' },
  { value: 'SOC2', label: 'SOC 2' },
  { value: 'HIPAA', label: 'HIPAA' },
];

interface VaptReportModalProps {
  open:       boolean;
  onClose:    () => void;
  provider:   ReportProvider;
  targetId:   string;
  targetName: string;
}

/**
 * "Generate VAPT Report" filter picker — Tags (all providers), plus Region
 * (AWS) or Resource Group (Azure) when the target actually has values for
 * them. Options come from the target's real open findings (vapt/filters),
 * never a static list, so nothing offered here can return an empty report.
 * Leaving everything unselected generates the full, unfiltered report.
 */
export function VaptReportModal({ open, onClose, provider, targetId, targetName }: VaptReportModalProps) {
  const [tags, setTags]                     = useState<string[]>([]);
  const [regions, setRegions]               = useState<string[]>([]);
  const [resourceGroups, setResourceGroups] = useState<string[]>([]);
  const [frameworks, setFrameworks]         = useState<string[]>([]);
  const [generating, setGenerating]         = useState(false);
  const [error, setError]                   = useState<string | null>(null);

  // Reset filter selections each time the modal is opened for a (possibly new) target.
  useEffect(() => {
    if (open) {
      setTags([]);
      setRegions([]);
      setResourceGroups([]);
      setFrameworks([]);
      setError(null);
    }
  }, [open, targetId]);

  const { data: options, isLoading } = useQuery({
    queryKey: ['vapt-filter-options', provider, targetId],
    queryFn:  () => reportsApi.getVaptFilterOptions(provider, targetId),
    enabled:  open,
  });

  const tagOptions      = (options?.tags ?? []).map(t => ({ value: t, label: t }));
  const regionOptions   = (options?.regions ?? []).map(r => ({ value: r, label: r }));
  const rgOptions       = (options?.resourceGroups ?? []).map(rg => ({ value: rg, label: rg }));

  const dynamicFrameworks = options?.frameworks?.map(f => ({ value: f.id, label: f.name }));
  const fallbackFrameworks = (provider === 'AWS' ? AWS_FRAMEWORKS : AZURE_FRAMEWORKS).slice(1);
  const frameworkOptions = dynamicFrameworks ?? fallbackFrameworks;

  const handleGenerate = async () => {
    setGenerating(true);
    setError(null);
    try {
      await reportsApi.openVaptReport(provider, targetId, {
        tags:          tags.length ? tags : undefined,
        region:        regions.length ? regions : undefined,
        resourceGroup: resourceGroups.length ? resourceGroups : undefined,
        frameworks:    frameworks.length ? frameworks : undefined,
        framework:     frameworks.length === 1 ? frameworks[0] : undefined,
      });
      onClose();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setGenerating(false);
    }
  };

  const activeFilterCount = tags.length + regions.length + resourceGroups.length + frameworks.length;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Generate VAPT Report"
      size="sm"
      contentClassName="!overflow-visible"
      footer={
        <>
          <Button variant="secondary" size="sm" onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            size="sm"
            leftIcon={<FileBarChart size={14} />}
            loading={generating}
            onClick={handleGenerate}
          >
            {activeFilterCount > 0 ? `Generate Report (${activeFilterCount} filter${activeFilterCount === 1 ? '' : 's'})` : 'Generate Full Report'}
          </Button>
        </>
      }
    >
      <div className="space-y-5">
        <p className="text-sm text-slate-600 leading-relaxed">
          <span className="font-semibold text-slate-900">{targetName}</span> — optionally narrow the
          report to specific tags{provider === 'AWS' && ', regions'}{provider === 'AZURE' && ', resource groups'}.
          Leave everything unselected for the full report.
        </p>

        {isLoading ? (
          <div className="flex items-center justify-center py-8 text-sm text-slate-400 font-medium bg-slate-50 rounded-xl border border-slate-100/50">Loading filter options…</div>
        ) : (
          <div className="space-y-4 bg-slate-50/50 p-4 rounded-xl border border-slate-100">
            {provider !== 'GCP' && (
              <div>
                <label className="block text-xs font-semibold tracking-wide text-slate-700 uppercase mb-1.5">Compliance Frameworks</label>
                <MultiSelect
                  options={frameworkOptions}
                  value={frameworks}
                  onChange={setFrameworks}
                  placeholder={frameworkOptions.length ? 'Select frameworks...' : 'All Frameworks (Full Report)'}
                />
              </div>
            )}
            
            <div>
              <label className="block text-xs font-semibold tracking-wide text-slate-700 uppercase mb-1.5">Tags</label>
              <MultiSelect
                options={tagOptions}
                value={tags}
                onChange={setTags}
                placeholder={tagOptions.length ? 'Select tags...' : 'No tagged findings'}
              />
            </div>

            {provider === 'AWS' && (
              <div>
                <label className="block text-xs font-semibold tracking-wide text-slate-700 uppercase mb-1.5 flex items-baseline gap-1.5">
                  Region
                  <span className="font-medium text-slate-400 normal-case tracking-normal">(not all findings have regions)</span>
                </label>
                <MultiSelect
                  options={regionOptions}
                  value={regions}
                  onChange={setRegions}
                  placeholder={regionOptions.length ? 'Select regions...' : 'No region data recorded'}
                />
              </div>
            )}

            {provider === 'AZURE' && (
              <div>
                <label className="block text-xs font-semibold tracking-wide text-slate-700 uppercase mb-1.5">Resource Group</label>
                <MultiSelect
                  options={rgOptions}
                  value={resourceGroups}
                  onChange={setResourceGroups}
                  placeholder={rgOptions.length ? 'Select resource groups...' : 'No resource group data recorded'}
                />
              </div>
            )}
          </div>
        )}

        {error && (
          <p className="text-sm text-red-700 bg-red-50 border border-red-200 rounded-lg px-4 py-3 shadow-sm">{error}</p>
        )}
      </div>
    </Modal>
  );
}
