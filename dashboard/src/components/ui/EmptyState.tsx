import React from 'react';
import { Button } from './Button';

export interface EmptyStateProps {
  icon: React.ElementType | React.ReactNode;
  title: string;
  description: string;
  action?: React.ReactNode;
  actionLabel?: string;
  onAction?: () => void;
  className?: string;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon: Icon,
  title,
  description,
  action,
  actionLabel,
  onAction,
  className = '',
}) => {
  const renderIcon = () => {
    if (!Icon) return null;
    if (React.isValidElement(Icon)) {
      return Icon;
    }
    if (typeof Icon === 'function' || (typeof Icon === 'object' && Icon !== null)) {
      const Component = Icon as React.ElementType;
      return <Component className="h-6 w-6 text-[#00B8FF] stroke-[1.8]" />;
    }
    return null;
  };

  return (
    <div className={`py-12 px-6 text-center space-y-4 max-w-md mx-auto ${className}`}>
      <div className="mx-auto h-12 w-12 rounded-xl bg-[#0A1424] border border-[#1C2B40] flex items-center justify-center">
        {renderIcon()}
      </div>
      <div className="space-y-1.5">
        <h4 className="text-sm font-bold text-[#F4F8FC]">{title}</h4>
        <p className="text-xs text-[#91A5BD] leading-relaxed">{description}</p>
      </div>
      {action ? (
        <div className="pt-2 flex justify-center">{action}</div>
      ) : actionLabel && onAction ? (
        <div className="pt-2 flex justify-center">
          <Button variant="primary" onClick={onAction}>
            {actionLabel}
          </Button>
        </div>
      ) : null}
    </div>
  );
};


