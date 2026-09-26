import type { CloudProvider } from '../../types';

export interface CloudProviderLogoProps {
  provider: CloudProvider | 'ALL' | string;
  className?: string;
  size?: 'sm' | 'md' | 'lg' | 'xl';
}

export function AwsLogo({ className = "h-4 w-4" }: { className?: string }) {
  return <img src="/img/aws-logo.svg" alt="AWS" className={`${className} object-contain`} />;
}

export function AzureLogo({ className = "h-4 w-4" }: { className?: string }) {
  return <img src="/img/azure-logo.svg" alt="Azure" className={`${className} object-contain`} />;
}

export function GcpLogo({ className = "h-4 w-4" }: { className?: string }) {
  return <img src="/img/gcp-logo.svg" alt="GCP" className={`${className} object-contain`} />;
}

export function CloudProviderLogo({ provider, className = "h-4 w-4" }: CloudProviderLogoProps) {
  const norm = (provider || '').toUpperCase();
  if (norm === 'AWS')   return <AwsLogo className={className} />;
  if (norm === 'AZURE') return <AzureLogo className={className} />;
  if (norm === 'GCP')   return <GcpLogo className={className} />;
  // ALL
  return (
    <svg className={`${className} text-blue-600 shrink-0`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z" />
    </svg>
  );
}

export default CloudProviderLogo;
