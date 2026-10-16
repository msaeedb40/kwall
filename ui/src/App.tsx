import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { MetricCards } from './components/MetricCards';
import { FlowsTable } from './components/FlowsTable';
import { ThreatsView } from './components/ThreatsView';
import { PoliciesView } from './components/PoliciesView';
import { DataplaneView } from './components/DataplaneView';
import {
  initialNodeStatus,
  initialFlows,
  initialSecurityAlerts,
  initialPolicies,
  ebpfMapsList,
  generateRandomFlow,
} from './mockData';
import type { FlowRecord, NodeStatus, SecurityAlert, PolicyRule, EbpfMapInfo } from './types';
import { ShieldAlert, Cpu, ArrowUpRight } from 'lucide-react';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [isStreaming, setIsStreaming] = useState<boolean>(true);
  const [status, setStatus] = useState<NodeStatus>(initialNodeStatus);
  const [flows, setFlows] = useState<FlowRecord[]>(initialFlows);
  const [alerts] = useState<SecurityAlert[]>(initialSecurityAlerts);
  const [policies] = useState<PolicyRule[]>(initialPolicies);
  const [maps] = useState<EbpfMapInfo[]>(ebpfMapsList);

  // Background live streaming simulator
  useEffect(() => {
    if (!isStreaming) return;

    const interval = setInterval(() => {
      const newFlow = generateRandomFlow();
      setFlows((prev) => [newFlow, ...prev.slice(0, 59)]);

      setStatus((prev) => ({
        ...prev,
        totalPackets: prev.totalPackets + newFlow.packets,
        totalBytes: prev.totalBytes + newFlow.bytes,
        droppedPackets: newFlow.verdict === 'DROP' ? prev.droppedPackets + newFlow.packets : prev.droppedPackets,
      }));
    }, 1800);

    return () => clearInterval(interval);
  }, [isStreaming]);

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Header
        status={status}
        isStreaming={isStreaming}
        onToggleStreaming={() => setIsStreaming(!isStreaming)}
        activeTab={activeTab}
        onSelectTab={setActiveTab}
      />

      <main style={{ flex: 1, padding: '28px 24px', maxWidth: '1600px', width: '100%', margin: '0 auto' }}>
        {activeTab === 'overview' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
            {/* Top Metric Cards */}
            <MetricCards status={status} />

            {/* Realtime Streams Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '24px', alignItems: 'start' }}>
              {/* Flows Stream Preview */}
              <div>
                <FlowsTable flows={flows.slice(0, 15)} />
              </div>

              {/* Side Panels: Active Threat Stream & Kernel Status */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                {/* Threat Center Quick Glance */}
                <div className="glass-panel" style={{ padding: '20px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <ShieldAlert size={18} color="var(--accent-crimson)" />
                      <h3 style={{ fontSize: '15px', fontWeight: 700, color: '#fff' }}>Recent Kernel Alerts</h3>
                    </div>
                    <button
                      onClick={() => setActiveTab('threats')}
                      style={{
                        background: 'transparent',
                        border: 'none',
                        color: 'var(--accent-cyan)',
                        fontSize: '12px',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '2px',
                      }}
                    >
                      View All <ArrowUpRight size={14} />
                    </button>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {alerts.slice(0, 3).map((a) => (
                      <div
                        key={a.id}
                        style={{
                          padding: '12px',
                          borderRadius: '6px',
                          background: 'var(--bg-secondary)',
                          border: '1px solid var(--border-subtle)',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '4px',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <span style={{ fontSize: '12px', fontWeight: 700, color: '#fff' }}>{a.type}</span>
                          <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>{a.timestamp}</span>
                        </div>
                        <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                          Target: {a.podName}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Netkit Fastpath status */}
                <div className="glass-panel" style={{ padding: '20px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                    <Cpu size={18} color="var(--accent-cyan)" />
                    <h3 style={{ fontSize: '15px', fontWeight: 700, color: '#fff' }}>Netkit Topology</h3>
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                    Direct BPF redirect fastpath is established across <strong>{status.activeInterfaces.length} interfaces</strong> with 0 skb copies.
                  </div>
                  <div style={{ marginTop: '14px', display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                    {status.activeInterfaces.map((iface) => (
                      <span
                        key={iface}
                        style={{
                          fontSize: '11px',
                          fontFamily: 'var(--font-mono)',
                          padding: '3px 8px',
                          borderRadius: '4px',
                          background: 'var(--bg-secondary)',
                          border: '1px solid var(--border-medium)',
                          color: 'var(--accent-cyan)',
                        }}
                      >
                        {iface}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'flows' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            <MetricCards status={status} />
            <FlowsTable flows={flows} />
          </div>
        )}

        {activeTab === 'threats' && <ThreatsView alerts={alerts} />}

        {activeTab === 'policies' && <PoliciesView policies={policies} />}

        {activeTab === 'dataplane' && <DataplaneView status={status} maps={maps} />}
      </main>
    </div>
  );
};

export default App;
