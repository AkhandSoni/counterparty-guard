import type React from 'react';

interface RiskMeterProps {
  score: number; // 0 to 100
}

export const RiskMeter: React.FC<RiskMeterProps> = ({ score }) => {
  const normalized = Math.max(0, Math.min(100, score));

  const getMeterColor = (val: number) => {
    if (val < 30) return 'bg-emerald-500 text-emerald-400';
    if (val < 70) return 'bg-amber-500 text-amber-400';
    return 'bg-rose-500 text-rose-400';
  };

  return (
    <div className="space-y-1.5">
      <div className="flex justify-between items-center text-xs">
        <span className="font-medium text-slate-300">Prototype Risk Indicator</span>
        <span className={`font-mono font-bold ${getMeterColor(normalized).split(' ')[1]}`}>
          {normalized}/100
        </span>
      </div>
      <div className="w-full bg-slate-800 h-2.5 rounded-full overflow-hidden border border-slate-700">
        <div
          className={`h-full transition-all duration-500 rounded-full ${getMeterColor(normalized).split(' ')[0]}`}
          style={{ width: `${normalized}%` }}
        />
      </div>
      <p className="text-[11px] text-slate-400 italic">
        Prototype heuristic indicator (0–100), not a statistical fraud probability.
      </p>
    </div>
  );
};
