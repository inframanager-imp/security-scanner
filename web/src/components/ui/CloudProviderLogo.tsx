import React from 'react';
import type { CloudProvider } from '../../types';

export interface CloudProviderLogoProps {
  provider: CloudProvider | 'ALL' | string;
  className?: string;
  size?: 'sm' | 'md' | 'lg' | 'xl';
}

/**
 * Official AWS Logo based on AWS Brand Guidelines (Image 1)
 */
export function AwsLogo({ className = "h-4 w-4" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 300 180" fill="none" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="AWS Logo">
      <g fill="#232F3E">
        {/* Letter 'a' */}
        <path d="M 44.5 106.8 c -6.8 0 -11.9 -2.6 -15 -7.7 l 0.3 -0.4 v 6.2 H 20.7 V 55.4 h 9.1 v 17 c 3.1 -4.8 8.1 -7.5 14.7 -7.5 12.1 0 20.5 9.1 20.5 22 0 13 -8.4 21.9 -20.5 21.9 z m -2.2 -8.5 c 7.5 0 12.5 -5.4 12.5 -13.5 0 -8.1 -5 -13.5 -12.5 -13.5 -7.4 0 -12.5 5.4 -12.5 13.5 0 8.1 5.1 13.5 12.5 13.5 z"/>
        {/* Letter 'w' */}
        <path d="M 125.4 105 H 116.1 L 98.7 65.5 L 81.3 105 H 72 L 51.5 55.4 h 9.7 l 15.4 39.5 L 94 55.4 h 9.4 l 17.4 39.5 L 136.2 55.4 h 9.7 Z"/>
        {/* Letter 's' */}
        <path d="M 172.8 106.8 c -12.1 0 -20.8 -4.2 -24.7 -11.6 l 7.7 -5.4 c 2.8 5.2 8.7 8.5 16.5 8.5 7.4 0 11.8 -3.1 11.8 -7.8 0 -4.3 -3.1 -6.6 -12.4 -8.7 l -5.4 -1.2 c -11.3 -2.6 -16.4 -8.1 -16.4 -16.8 0 -11.2 9.9 -18.7 24.3 -18.7 10.9 0 18.9 3.7 23.3 10.6 l -7.4 5.4 c -3.1 -4.7 -8.2 -7.5 -15.4 -7.5 -6.7 0 -10.9 2.9 -10.9 7 0 3.7 2.8 5.8 11.2 7.7 l 5.4 1.2 c 12.4 2.8 17.6 8.3 17.6 17.3 0 11.4 -9.3 20 -24.7 20 Z"/>
      </g>
      {/* Official Orange Smile Arrow in #FF9900 */}
      <path d="M 235.8 131 c -35.2 24.8 -86.3 37.9 -130.3 37.9 -61.2 0 -116.4 -22.3 -157.9 -59.5 -3.1 -2.8 -0.5 -7.2 3.6 -5.2 56.8 33.7 126.7 53.8 195.4 53.8 38.9 0 82.2 -9.8 117.2 -30.5 5.8 -3.4 10.4 2.7 5 6.9 z" fill="#FF9900"/>
      <path d="M 251.3 115.5 c -3.7 -4.7 -24.8 -2.1 -34.1 -1 -2.6 0.3 -3.1 -2.1 -0.5 -4.1 5.7 -4.7 26.9 -6.7 32.5 -1 5.6 5.7 3.1 25.8 -0.1 32.5 -1.5 2.1 -3.6 1.8 -4.1 -0.5 1 -6.7 4.1 -21.7 6.3 -25.9 z" fill="#FF9900"/>
    </svg>
  );
}

/**
 * Official Microsoft Azure Logo based on Fluent Guidelines (Image 2)
 */
export function AzureLogo({ className = "h-4 w-4" }: { className?: string }) {
  const idSuffix = React.useId().replace(/:/g, '');
  const gradLeftId = `azure_g1_${idSuffix}`;
  const gradRightId = `azure_g2_${idSuffix}`;

  return (
    <svg className={className} viewBox="0 0 96 96" fill="none" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Azure Logo">
      <defs>
        <linearGradient id={gradLeftId} x1="0%" y1="100%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#114A8B"/>
          <stop offset="100%" stopColor="#0669BC"/>
        </linearGradient>
        <linearGradient id={gradRightId} x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#3CCBF4"/>
          <stop offset="100%" stopColor="#2892DF"/>
        </linearGradient>
      </defs>
      {/* Left side trapezoid */}
      <path fill={`url(#${gradLeftId})`} d="M32.8 12h27.4L32.2 84H12L32.8 12z"/>
      {/* Right ribbon fold */}
      <path fill={`url(#${gradRightId})`} d="M60.2 12L32.8 84h24.8l14.6-28.7H96L60.2 12z"/>
    </svg>
  );
}

/**
 * Official GCP Logo
 */
export function GcpLogo({ className = "h-4 w-4" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 512 512" fill="none" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="GCP Logo">
      <path d="M380 236h-13.7v-2.3c0-57.5-46.6-104.1-104.1-104.1-43.9 0-81.5 27.2-96.6 65.8-9.4-5.2-20.2-8.1-31.8-8.1-35.8 0-64.8 29-64.8 64.8 0 4.1.4 8.1 1.1 12-38.3 7.8-67.1 41.6-67.1 82.1 0 46.4 37.6 84 84 84h293c40.3 0 73-32.7 73-73 0-38.9-30.5-70.8-69-72.2z" fill="#4285F4"/>
      <path d="M262.2 129.6c-43.9 0-81.5 27.2-96.6 65.8-9.4-5.2-20.2-8.1-31.8-8.1-35.8 0-64.8 29-64.8 64.8 0 4.1.4 8.1 1.1 12H380v-2.3c0-57.5-46.6-104.2-104.1-104.2z" fill="#EA4335"/>
      <path d="M380 236h-13.7c0-57.5-46.6-104.1-104.1-104.1v218.4H380c40.3 0 73-32.7 73-73 0-38.9-30.5-70.8-69-72.2z" fill="#FBBC05"/>
      <path d="M133.8 264.1c0-35.8 29-64.8 64.8-64.8 11.6 0 22.4 2.9 31.8 8.1 15.1-38.6 52.7-65.8 96.6-65.8V350H70c-46.4 0-84-37.6-84-84 0-40.5 28.8-74.3 67.1-82.1-.7-3.9-1.1-7.9-1.1-12z" fill="#34A853" opacity="0.9"/>
    </svg>
  );
}

export function CloudProviderLogo({ provider, className = "h-4 w-4" }: CloudProviderLogoProps) {
  const norm = (provider || '').toUpperCase();
  if (norm === 'AWS') return <AwsLogo className={className} />;
  if (norm === 'AZURE') return <AzureLogo className={className} />;
  if (norm === 'GCP') return <GcpLogo className={className} />;
  return <span className="text-xs">☁️</span>;
}

export default CloudProviderLogo;
