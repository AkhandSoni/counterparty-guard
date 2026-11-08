import type React from 'react';
import { useState } from 'react';
import { Footer } from './components/Footer';
import { Header } from './components/Header';
import type { Network, PendingWarningContext } from './types';
import { CheckActionView } from './views/CheckActionView';
import { EvidenceTimeline } from './views/EvidenceTimeline';
import { ReviewerPortal } from './views/ReviewerPortal';
import { WarningApproval } from './views/WarningApproval';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'checks' | 'evidence' | 'approvals' | 'moderation'>(
    'checks',
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
