import { useState, useRef, useEffect, type SelectHTMLAttributes } from 'react';
import { ChevronDown, Check } from 'lucide-react';
import clsx from 'clsx';

export interface SelectOption {
  value: string;
  label: string;
}

export interface SelectProps extends Omit<SelectHTMLAttributes<HTMLSelectElement>, 'onChange' | 'value'> {
  label?: string;
  error?: string;
  options: SelectOption[];
  placeholder?: string;
  value?: string;
  onChange?: (e: { target: { value: string } }) => void;
  className?: string;
  disabled?: boolean;
}

export function Select({
  label,
  error,
  options,
  placeholder,
  value = '',
  onChange,
  className,
  disabled,
  id,
}: SelectProps) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  const selectId = id ?? label?.toLowerCase().replace(/\s+/g, '-');

  // Close on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, []);

  const selectedOption = options.find((o) => o.value === value);
  const displayLabel = selectedOption
    ? selectedOption.label
    : (placeholder ?? (options.length > 0 ? options[0].label : 'Select...'));

  const isPlaceholder = !selectedOption && placeholder;

  const handleSelect = (optValue: string) => {
    if (onChange) {
      onChange({ target: { value: optValue } } as any);
    }
    setOpen(false);
  };

  return (
    <div ref={ref} className="flex flex-col gap-1 relative">
      {label && (
        <label
          htmlFor={selectId}
          className="block text-xs font-semibold text-gray-700"
        >
          {label}
        </label>
      )}
      <div className="relative">
        <button
          type="button"
          id={selectId}
          disabled={disabled}
          onClick={() => setOpen((p) => !p)}
          className={clsx(
            'flex items-center justify-between w-full rounded-lg border bg-white px-3 py-2 text-xs sm:text-sm shadow-2xs transition-all cursor-pointer text-left',
            open
              ? 'border-blue-600 ring-2 ring-blue-500/20'
              : 'border-gray-300/90 hover:border-gray-400',
            error && 'border-red-300 focus:border-red-500 focus:ring-red-500',
            disabled && 'bg-gray-50 text-gray-500 cursor-not-allowed',
            className,
          )}
        >
          <span
            className={clsx(
              'truncate',
              isPlaceholder ? 'text-gray-400 font-normal' : 'text-gray-900 font-medium',
            )}
          >
            {displayLabel}
          </span>
          <ChevronDown
            size={14}
            className={clsx(
              'text-gray-400 shrink-0 ml-2 transition-transform duration-200',
              open && 'rotate-180 text-blue-600',
            )}
          />
        </button>

        {open && (
          <div className="absolute z-50 mt-1.5 w-full min-w-[150px] rounded-xl border border-gray-200/90 bg-white shadow-xl py-1 overflow-hidden">
            <div className="max-h-60 overflow-y-auto py-1">
              {options.length === 0 && (
                <div className="px-3 py-2 text-xs text-gray-400">No options</div>
              )}
              {options.map((opt) => {
                const isSelected = opt.value === value;
                return (
                  <button
                    key={opt.value}
                    type="button"
                    onClick={() => handleSelect(opt.value)}
                    className={clsx(
                      'flex items-center justify-between w-full px-3 py-2 text-xs sm:text-sm text-left cursor-pointer transition-colors',
                      isSelected
                        ? 'bg-blue-50/80 text-blue-700 font-semibold'
                        : 'text-gray-700 hover:bg-gray-50/80 hover:text-gray-900',
                    )}
                  >
                    <span className="truncate">{opt.label}</span>
                    {isSelected && <Check size={14} className="text-blue-600 shrink-0 ml-2" />}
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </div>
      {error && <p className="text-xs text-red-600">{error}</p>}
    </div>
  );
}
