import { useState, useRef, useEffect } from 'react';
import { ChevronDown, X } from 'lucide-react';
import clsx from 'clsx';

interface Option {
  value: string;
  label: string;
}

interface MultiSelectProps {
  options: Option[];
  value: string[];
  onChange: (values: string[]) => void;
  placeholder?: string;
  className?: string;
}

export function MultiSelect({
  options,
  value,
  onChange,
  placeholder = 'Select...',
  className,
}: MultiSelectProps) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

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

  const toggle = (v: string) => {
    if (value.includes(v)) {
      onChange(value.filter((x) => x !== v));
    } else {
      onChange([...value, v]);
    }
  };

  const clearAll = (e: React.MouseEvent) => {
    e.stopPropagation();
    onChange([]);
  };

  const label =
    value.length === 0
      ? placeholder
      : value.length === 1
      ? options.find((o) => o.value === value[0])?.label ?? value[0]
      : `${value.length} selected`;

  return (
    <div ref={ref} className={clsx('relative', className)}>
      <button
        type="button"
        onClick={() => setOpen((p) => !p)}
        className="flex items-center justify-between w-full rounded-lg border border-gray-300/90 bg-white px-3 py-2 text-xs sm:text-sm text-gray-700 shadow-2xs hover:border-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-600 transition-all cursor-pointer"
      >
        <span className={value.length === 0 ? 'text-gray-400 font-normal' : 'font-medium'}>{label}</span>
        <span className="flex items-center gap-1 ml-2 shrink-0">
          {value.length > 0 && (
            <X
              size={12}
              className="text-gray-400 hover:text-gray-600"
              onClick={clearAll}
            />
          )}
          <ChevronDown
            size={14}
            className={clsx('text-gray-400 transition-transform duration-200', open && 'rotate-180')}
          />
        </span>
      </button>

      {open && (
        <div className="absolute z-50 mt-1.5 w-full min-w-max rounded-xl border border-gray-200/90 bg-white shadow-xl py-1 overflow-hidden">
          <div className="max-h-40 overflow-y-auto py-1">
            {options.length === 0 && (
              <div className="px-3 py-2 text-xs text-gray-400">No options</div>
            )}
            {options.map((opt) => (
              <label
                key={opt.value}
                className="flex items-center gap-2 px-3 py-1.5 text-sm text-gray-700 hover:bg-gray-50 cursor-pointer"
              >
                <input
                  type="checkbox"
                  checked={value.includes(opt.value)}
                  onChange={() => toggle(opt.value)}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                {opt.label}
              </label>
            ))}
          </div>
          <div className="flex items-center justify-between border-t border-slate-100 px-3 py-2 bg-slate-50/50">
            <button
              type="button"
              onClick={() => onChange([])}
              disabled={value.length === 0}
              className={clsx(
                "text-xs font-medium transition-colors",
                value.length === 0
                  ? "text-slate-400 cursor-not-allowed opacity-60"
                  : "text-slate-500 hover:text-slate-700"
              )}
            >
              Clear all
            </button>
            <button
              type="button"
              onClick={() => setOpen(false)}
              className="text-xs font-semibold text-blue-600 hover:text-blue-700 transition-colors bg-blue-50 hover:bg-blue-100 px-3 py-1.5 rounded-md"
            >
              Done
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
