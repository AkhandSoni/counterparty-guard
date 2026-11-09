import type React from 'react';
import { useState } from 'react';
import { Footer } from './components/Footer';
import { Header } from './components/Header';
import type { Network, PendingWarningContext } from './types';
import { CheckActionView } from './views/CheckActionView';
import { EvidenceTimeline } from './views/EvidenceTimeline';
import { ReviewerPortal } from './views/ReviewerPortal';
import { WarningApproval } from './views/WarningApproval';
import { ApiCheckView } from './views/ApiCheckView';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'api' | 'checks' | 'evidence' | 'approvals' | 'moderation'>(
    'api',
  );
  const [network, setNetwork] = useState<Network>('testnet');
  const [pendingWarningContext, setPendingWarningContext] = useState<PendingWarningContext | null>(
    null,
  );

  const handleNavigateToApprovals = (context?: PendingWarningContext) => {
    if (context) {
      setPendingWarningContext(context);
    }
    setActiveTab('approvals');
  };

  return (
    <div className="min-h-screen flex flex-col bg-slate-950 text-slate-100">
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        network={network}
        setNetwork={setNetwork}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab !== 'api' && <aside className="mb-5 p-3 border border-amber-700 rounded text-sm text-amber-200">Offline examples only. The sample decisions, report reviews and approval previews do not change the API or authorize payments. Use Connected API for actual assessments and report reviews.</aside>}
        {activeTab === 'api' && <ApiCheckView />}
        {activeTab === 'checks' && (
          <CheckActionView onNavigateToApprovals={handleNavigateToApprovals} />
        )}
        {activeTab === 'evidence' && <EvidenceTimeline />}
        {activeTab === 'approvals' && <WarningApproval context={pendingWarningContext} />}
        {activeTab === 'moderation' && <ReviewerPortal />}
      </main>

      <Footer />
    </div>
  );
};

export default App;
