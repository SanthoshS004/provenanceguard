import React from 'react';

export interface PageHeaderProps {
  category: string;
  title: string;
  description: string;
  actions?: React.ReactNode;
}

export const PageHeader: React.FC<PageHeaderProps> = ({
  category,
  title,
  description,
  actions,
}) => {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-[#1C2B40]">
      <div>
        <span className="text-[10px] font-extrabold tracking-widest text-[#00B8FF] uppercase">
          {category}
        </span>
        <h2 className="text-xl md:text-2xl font-extrabold tracking-tight text-slate-100 mt-0.5">
          {title}
        </h2>
        <p className="text-xs font-medium text-slate-400 mt-0.5">
          {description}
        </p>
      </div>

      {actions && (
        <div className="flex items-center gap-3 shrink-0 self-start sm:self-auto">
          {actions}
        </div>
      )}
    </div>
  );
};
