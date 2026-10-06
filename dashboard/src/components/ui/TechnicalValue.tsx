import React from 'react';

export interface TechnicalValueProps {
  value: string;
  truncate?: boolean;
  truncateLength?: number;
  className?: string;
  copyable?: boolean;
}

export const TechnicalValue: React.FC<TechnicalValueProps> = ({
  value,
  truncate = false,
  truncateLength = 12,
  className = '',
  copyable = false,
}) => {
  const [copied, setCopied] = React.useState(false);

  if (!value) return <span className="text-slate-400 font-mono text-xs">—</span>;

  const displayValue =
    truncate && value.length > truncateLength
      ? `${value.slice(0, Math.ceil(truncateLength / 2))}...${value.slice(-Math.floor(truncateLength / 2))}`
      : value;

  const handleCopy = () => {
    if (!copyable) return;
    navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <span
      onClick={handleCopy}
      title={copyable ? `Click to copy full value: ${value}` : value}
      className={`font-mono text-xs select-all break-all ${
        copyable ? 'cursor-pointer hover:text-sky-400 transition-colors' : ''
      } ${className}`}
    >
      {displayValue}
      {copied && <span className="ml-1.5 text-[10px] text-emerald-400 font-sans">✓ Copied</span>}
    </span>
  );
};
