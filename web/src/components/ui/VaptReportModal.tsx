import { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { FileBarChart } from 'lucide-react';
import { reportsApi, type ReportProvider } from '../../api/reports';
import { Modal } from './Modal';
import { Button } from './Button';
import { MultiSelect } from './MultiSelect';

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
  const [generating, setGenerating]         = useState(false);
  const [error, setError]                   = useState<string | null>(null);

  // Reset filter selections each time the modal is opened for a (possibly new) target.
  useEffect(() => {
    if (open) {
      setTags([]);
      setRegions([]);
      setResourceGroups([]);
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

  const handleGenerate = async () => {
    setGenerating(true);
    setError(null);
    try {
      await reportsApi.openVaptReport(provider, targetId, {
        tags:          tags.length ? tags : undefined,
        region:        regions.length ? regions : undefined,
        resourceGroup: resourceGroups.length ? resourceGroups : undefined,
      });
      onClose();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setGenerating(false);
    }
  };

  const activeFilterCount = tags.length + regions.length + resourceGroups.length;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Generate VAPT Report"
      size="sm"
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
      <div className="space-y-4">
        <p className="text-sm text-gray-500">
          <span className="font-medium text-gray-700">{targetName}</span> — optionally narrow the
          report to specific tags{provider === 'AWS' && ', regions'}{provider === 'AZURE' && ', resource groups'}.
          Leave everything unselected for the full report.
        </p>

        {isLoading ? (
          <div className="flex items-center justify-center py-6 text-sm text-gray-400">Loading filter options…</div>
        ) : (
          <div className="space-y-3">
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Tags</label>
              <MultiSelect
                options={tagOptions}
                value={tags}
                onChange={setTags}
                placeholder={tagOptions.length ? 'All tags' : 'No tagged findings'}
              />
            </div>

            {provider === 'AWS' && (
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">
                  Region
                  <span className="ml-1 font-normal text-gray-400">(best-effort — not every finding records a region)</span>
                </label>
                <MultiSelect
                  options={regionOptions}
                  value={regions}
                  onChange={setRegions}
                  placeholder={regionOptions.length ? 'All regions' : 'No region data recorded'}
                />
              </div>
            )}

            {provider === 'AZURE' && (
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Resource Group</label>
                <MultiSelect
                  options={rgOptions}
                  value={resourceGroups}
                  onChange={setResourceGroups}
                  placeholder={rgOptions.length ? 'All resource groups' : 'No resource group data recorded'}
                />
              </div>
            )}
          </div>
        )}

        {error && (
          <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded px-3 py-2">{error}</p>
        )}
      </div>
    </Modal>
  );
}
