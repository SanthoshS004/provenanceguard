import React from 'react';
import { CheckCircle2, AlertTriangle, ShieldX, Info, Clock, Loader2 } from 'lucide-react';

export type DecisionStatus =
  | 'PASS'
  | 'PASS_WITH_WARNING'
  | 'WARNING'
  | 'BLOCK'
  | 'FAILED'
  | 'QUEUED'
  | 'RUNNING'
  | 'SUCCEEDED'
  | 'COMPLETED'
  | 'INFO'
  | 'NEUTRAL';

export interface BadgeProps {
  status?: DecisionStatus | string;
  variant?: DecisionStatus | string;
  label?: string;
  children?: React.ReactNode;
  className?: string;
}

export const Badge: React.FC<BadgeProps> = ({ status, variant, label, children, className = '' }) => {
  const rawStatus = status || variant || (typeof children === 'string' ? children : '') || '';
  const textLabel = label || (typeof children === 'string' ? children : '') || rawStatus;
  const normalized = rawStatus.toUpperCase();

  if (normalized === 'PASS' || normalized === 'SUCCEEDED' || normalized === 'COMPLETED' || normalized === 'ACTIVE' || normalized === 'VERIFIED' || normalized === 'LAYER DIFF CLEAN' || normalized === 'INCLUSION VERIFIED' || normalized === 'AUTHORIZED REGEX MATCH' || normalized === 'SLSA LEVEL 3' || normalized === 'W^X HARDENED' || normalized === 'ALL INERT SAFE' || normalized === 'MATCH / PATCH') {
    return (
      <span className={`badge-pass ${className}`}>
        <CheckCircle2 className="h-3.5 w-3.5" />
        <span>{textLabel}</span>
      </span>
    );
  }

  if (normalized === 'PASS_WITH_WARNING' || normalized === 'WARNING' || normalized === 'VERSION SHIFT') {
    return (
      <span className={`badge-warning ${className}`}>
        <AlertTriangle className="h-3.5 w-3.5" />
        <span>{textLabel}</span>
      </span>
    );
  }

  if (normalized === 'BLOCK' || normalized === 'FAILED' || normalized === 'REVOKED' || normalized === 'INACTIVE' || normalized === 'UNEXPECTED ADDITION') {
    return (
      <span className={`badge-block ${className}`}>
        <ShieldX className="h-3.5 w-3.5" />
        <span>{textLabel}</span>
      </span>
    );
  }

  if (normalized === 'RUNNING') {
    return (
      <span className={`badge-info ${className}`}>
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
        <span>{textLabel}</span>
      </span>
    );
  }

  if (normalized === 'QUEUED') {
    return (
      <span className={`badge-neutral ${className}`}>
        <Clock className="h-3.5 w-3.5" />
        <span>{textLabel}</span>
      </span>
    );
  }

  if (normalized === 'INFO') {
    return (
      <span className={`badge-info ${className}`}>
        <Info className="h-3.5 w-3.5" />
        <span>{textLabel}</span>
      </span>
    );
  }

  return (
    <span className={`badge-neutral ${className}`}>
      <span>{textLabel || 'UNKNOWN'}</span>
    </span>
  );
};

