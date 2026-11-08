import type React from 'react';

export const Footer: React.FC = () => {
  return (
    <footer className="mt-12 border-t border-slate-800 bg-slate-950/80 py-6 text-xs text-slate-400">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-2">
        <div className="flex flex-col md:flex-row items-center justify-between gap-4">
          <p className="flex items-center gap-2">
            <span className="font-semibold text-slate-300">Security Invariant:</span>
            Raw report counts cannot create a hard block. Human reviewer authentication required for
            blocklist activation.
          </p>
          <div className="flex items-center gap-4 text-slate-400">
            <span>Milestone 1 Shell</span>
            <span>•</span>
            <span>NEAR Hackathon Showcase</span>
          </div>
        </div>
        <p className="text-[11px] text-slate-400">
          Counterparty Guard Agent C Deliverables: signed intake, Sybil graph analysis, faucet
          exemptions, and owner warning approval guidance.
        </p>
      </div>
    </footer>
  );
};
