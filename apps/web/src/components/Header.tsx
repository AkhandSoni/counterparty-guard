import type React from 'react';
import type { Network } from '../types';
import { ShieldCheckIcon } from './Icons';

interface HeaderProps {
  activeTab: 'checks' | 'evidence' | 'approvals' | 'moderation';
  setActiveTab: (tab: 'checks' | 'evidence' | 'approvals' | 'moderation') => void;
  network: Network;
  setNetwork: (network: Network) => void;
}

export const Header: React.FC<HeaderProps> = ({ activeTab, setActiveTab, network, setNetwork }) => {
  return (
    <header className="border-b border-slate-800 bg-slate-900/90 backdrop-blur sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand */}
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-cyan-950 border border-cyan-800 text-cyan-400">
              <ShieldCheckIcon size={24} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="font-bold text-lg text-white tracking-tight">Counterparty Guard</h1>
                <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-cyan-900/60 border border-cyan-700 text-cyan-300">
                  Agent C
                </span>
              </div>
              <p className="text-xs text-slate-400">NEAR Reputation & Experience Engine</p>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="flex items-center gap-1 bg-slate-950 p-1 rounded-xl border border-slate-800">
            <button
              type="button"
              onClick={() => setActiveTab('checks')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                activeTab === 'checks'
                  ? 'bg-cyan-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              Check Action
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('evidence')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                activeTab === 'evidence'
                  ? 'bg-cyan-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              Evidence Timeline
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('approvals')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                activeTab === 'approvals'
                  ? 'bg-cyan-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              Warning Approvals
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('moderation')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                activeTab === 'moderation'
                  ? 'bg-purple-700 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              Reviewer Portal
            </button>
          </nav>

          {/* Network & Status */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 text-xs">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-slate-400">Mode:</span>
              <span className="font-mono text-cyan-400 font-semibold">Fixture Offline</span>
            </div>

            <select
              value={network}
              onChange={(e) => setNetwork(e.target.value as Network)}
              className="bg-slate-800 border border-slate-700 text-slate-200 rounded-lg text-xs px-2.5 py-1.5 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
            >
              <option value="testnet">NEAR Testnet</option>
              <option value="sandbox">Local Sandbox</option>
              <option value="mainnet">NEAR Mainnet</option>
            </select>
          </div>
        </div>
      </div>
    </header>
  );
};
