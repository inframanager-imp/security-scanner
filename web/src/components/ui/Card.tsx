import type { ReactNode } from 'react';
import clsx from 'clsx';

interface CardProps {
  title?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  padding?: boolean;
}

export function Card({ title, action, children, className, padding = true }: CardProps) {
  return (
    <div
      className={clsx(
        'bg-white rounded-lg shadow-sm border border-gray-200 flex flex-col',
        className,
      )}
    >
      {(title || action) && (
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 shrink-0">
          {title && (
            <h3 className="text-base font-semibold text-gray-900">{title}</h3>
          )}
          {action && <div className="flex items-center gap-2">{action}</div>}
        </div>
      )}
      <div className={clsx(padding && 'p-6', 'flex-1 flex flex-col')}>{children}</div>
    </div>
  );
}

interface StatCardProps {
  title: string;
  value: string | number;
  icon?: ReactNode;
  trend?: { value: number; label: string };
  className?: string;
  valueClassName?: string;
}

export function StatCard({
  title,
  value,
  icon,
  className,
  valueClassName,
}: StatCardProps) {
  return (
    <div
      className={clsx(
        'bg-white rounded-lg shadow-sm border border-gray-200 p-6',
        className,
      )}
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-500">{title}</p>
          <p className={clsx('mt-1 text-3xl font-bold text-gray-900', valueClassName)}>
            {value}
          </p>
        </div>
        {icon && (
          <div className="h-12 w-12 rounded-full bg-blue-50 flex items-center justify-center text-blue-600">
            {icon}
          </div>
        )}
      </div>
    </div>
  );
}
