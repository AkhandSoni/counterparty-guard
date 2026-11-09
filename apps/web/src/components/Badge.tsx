import type React from 'react';
import type { Decision } from '../types';
import { AlertTriangleIcon, BanIcon, CheckCircleIcon, ShieldIcon } from './Icons';

interface BadgeProps {
  decision: Decision;
  size?: 'sm' | 'md' | 'lg';
}

export const DecisionBadge: React.FC<BadgeProps> = ({ decision, size = 'md' }) => {
  const configs = {
    allow: {
      label: 'ALLOW',
      classes: 'bg-emerald-950/80 border-emerald-500 text-emerald-300 ring-emerald-500/20',
      icon: <CheckCircleIcon size={size === 'lg' ? 24 : 16} className="text-emerald-400" />,
    },
    warn: {
      label: 'WARN',
      classes: 'bg-amber-950/80 border-amber-500 text-amber-300 ring-amber-500/20',
      icon: <AlertTriangleIcon size={size === 'lg' ? 24 : 16} className="text-amber-400" />,
    },
    block: {
      label: 'BLOCK',
      classes: 'bg-rose-950/80 border-rose-500 text-rose-300 ring-rose-500/20',
      icon: <BanIcon size={size === 'lg' ? 24 : 16} className="text-rose-400" />,
    },
    error: {
      label: 'ERROR',
      classes: 'bg-slate-800 border-slate-600 text-slate-300 ring-slate-500/20',
      icon: <ShieldIcon size={size === 'lg' ? 24 : 16} className="text-slate-400" />,
    },
  };

  const config = configs[decision];
  const sizeClasses = {
    sm: 'px-2 py-0.5 text-xs',
    md: 'px-3 py-1 text-sm font-semibold',
    lg: 'px-5 py-2 text-xl font-bold tracking-wider',
  }[size];

  return (
    <span
      className={`inline-flex items-center gap-2 rounded-full border ring-1 ${config.classes} ${sizeClasses}`}
    >
      {config.icon}
      {config.label}
    </span>
  );
};
