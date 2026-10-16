import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { Header } from './components/Header';
import { MetricCards } from './components/MetricCards';
import { FlowsTable } from './components/FlowsTable';
import { ThreatsView } from './components/ThreatsView';
import { PoliciesView } from './components/PoliciesView';
import { DataplaneView } from './components/DataplaneView';
import { KwallApiClient, KwallTelemetryStreamer } from './services';
import type {
  IKwallNodeStatus,
  IKwallFlowRecord,
  IKwallSecurityAlert,
  IKwallPolicyRule,
  IKwallEbpfMap,
  IKwallBlacklistEntry,
  StreamConnectionStatus,
} from './types';
import { ShieldAlert, Cpu, ArrowUpRight } from 'lucide-react';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [isStreaming, setIsStreaming] = useState<boolean>(true);
  const [streamStatus, setStreamStatus] = useState<StreamConnectionStatus>('OFFLINE');

  // Client Services (Divide and conquer architecture)
  const apiClient = useMemo(() => new KwallApiClient(), []);
  const streamer = useMemo(() => new KwallTelemetryStreamer(), []);

  // State
  const [status, setStatus] = useState<IKwallNodeStatus | null>(null);
  const [flows, setFlows] = useState<IKwallFlowRecord[]>([]);
  const [alerts, setAlerts] = useState<IKwallSecurityAlert[]>([]);
  const [policies, setPolicies] = useState<IKwallPolicyRule[]>([]);
  const [maps, setMaps] = useState<IKwallEbpfMap[]>([]);
  const [blacklist, setBlacklist] = useState<IKwallBlacklistEntry[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Initial data loading from API Client
  useEffect(() => {
    let isMounted = true;
    setIsLoading(true);

    Promise.all([
      apiClient.fetchNodeStatus(),
      apiClient.fetchThreatAlerts(),
      apiClient.fetchPolicies(),
      apiClient.fetchEbpfMaps(),
      apiClient.fetchBlacklist(),
    ])
      .then(([nodeStatus, threatAlerts, pols, ebpfMaps, bl]) => {
        if (!isMounted) return;
        setStatus(nodeStatus);
        setAlerts(threatAlerts);
        setPolicies(pols);
        setMaps(ebpfMaps);
        setBlacklist(bl);
      })
      .catch((err) => {
        console.error('Initial data fetch error:', err);
      })
      .finally(() => {
        if (isMounted) setIsLoading(false);
      });

    return () => {
      isMounted = false;
    };
  }, [apiClient]);

  // Live eBPF Telemetry Streaming with capped sliding memory window
  useEffect(() => {
    if (!isStreaming) {
      streamer.stop();
      return;
    }

    streamer.start();

    const subscription = streamer.subscribe(
      (flow: IKwallFlowRecord) => {
        // High-performance bounded sliding window (Divide & conquer memory management)
        setFlows((prev) => [flow, ...prev.slice(0, 99)]);

        setStatus((prev) => {
          if (!prev) return prev;
          return {
            ...prev,
            totalPackets: prev.totalPackets + flow.packets,
            totalBytes: prev.totalBytes + flow.bytes,
            droppedPackets: flow.verdict === 'DROP' ? prev.droppedPackets + flow.packets : prev.droppedPackets,
          };
        });
      },
      (newStatus: StreamConnectionStatus) => {
        setStreamStatus(newStatus);
      }
    );

    return () => {
      subscription.unsubscribe();
      streamer.stop();
    };
  }, [isStreaming, streamer]);

  // Mutators for blacklist
  const handleAddBlacklist = useCallback(
    async (ip: string, reason: string) => {
      const entry = await apiClient.addToBlacklist(ip, reason);
      setBlacklist((prev) => [entry, ...prev]);
    },
    [apiClient]
  );

  const handleRemoveBlacklist = useCallback(
    async (ip: string) => {
      await apiClient.removeFromBlacklist(ip);
      setBlacklist((prev) => prev.filter((item) => item.ip !== ip));
    },
    [apiClient]
  );

  if (isLoading || !status) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center text-slate-400 gap-4" role="status" aria-live="polite">
        <div className="w-12 h-12 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin" />
        <span className="text-sm font-mono tracking-wider">INITIALIZING KWALL EBPF DATAPLANE CLIENT...</span>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col bg-slate-950 text-slate-100">
      <Header
        status={status}
        streamStatus={streamStatus}
        isStreaming={isStreaming}
        onToggleStreaming={() => setIsStreaming(!isStreaming)}
        activeTab={activeTab}
        onSelectTab={setActiveTab}
      />

      <main className="flex-1 px-4 sm:px-6 py-6 max-w-7xl w-full mx-auto" id="main-content" tabIndex={-1}>
        <div className="sr-only" aria-live="polite" aria-atomic="true">
          Current view: {activeTab}. Live streaming status is {streamStatus}.
        </div>

        {activeTab === 'overview' && (
          <div className="flex flex-col gap-6">
            {/* Top Metric Cards */}
            <MetricCards status={status} />

            {/* Realtime Streams Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
              {/* Flows Stream Preview (2 cols on large screens) */}
              <div className="lg:col-span-2">
                <FlowsTable flows={flows.slice(0, 15)} />
              </div>

              {/* Side Panels */}
              <div className="flex flex-col gap-6">
                {/* Threat Center Quick Glance */}
                <div className="glass-panel p-5 shadow-lg">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4 text-rose-500" />
                      <h3 className="text-sm font-bold text-white">Recent Security Alerts</h3>
                    </div>
                    <button
                      onClick={() => setActiveTab('threats')}
                      className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-semibold focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyan-400 rounded"
                    >
                      View All <ArrowUpRight className="w-3.5 h-3.5" />
                    </button>
                  </div>

                  <div className="flex flex-col gap-2.5">
                    {alerts.slice(0, 3).map((a) => (
                      <div
                        key={a.id}
                        className="p-3 rounded-lg bg-slate-900 border border-white/10 flex flex-col gap-1"
                      >
                        <div className="flex justify-between items-center text-xs">
                          <span className="font-bold text-white">{a.type}</span>
                          <span className="text-[10px] font-mono text-slate-500">{a.timestamp}</span>
                        </div>
                        <span className="text-[11px] text-slate-400 truncate">
                          Target: {a.podName}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Netkit Fastpath status */}
                <div className="glass-panel p-5 shadow-lg">
                  <div className="flex items-center gap-2 mb-3">
                    <Cpu className="w-4 h-4 text-cyan-400" />
                    <h3 className="text-sm font-bold text-white">Netkit Topology</h3>
                  </div>
                  <div className="text-xs text-slate-400 leading-relaxed">
                    Direct BPF redirect fastpath is established across <strong className="text-white">{status.activeInterfaces.length} interfaces</strong> with 0 skb copies.
                  </div>
                  <div className="mt-3.5 flex gap-1.5 flex-wrap">
                    {status.activeInterfaces.map((iface) => (
                      <span
                        key={iface}
                        className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-900 border border-white/10 text-cyan-400"
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
          <div className="flex flex-col gap-6">
            <MetricCards status={status} />
            <FlowsTable flows={flows} />
          </div>
        )}

        {activeTab === 'threats' && (
          <ThreatsView
            alerts={alerts}
            blacklist={blacklist}
            onAddBlacklist={handleAddBlacklist}
            onRemoveBlacklist={handleRemoveBlacklist}
          />
        )}

        {activeTab === 'policies' && (
          <PoliciesView policies={policies} apiClient={apiClient} />
        )}

        {activeTab === 'dataplane' && (
          <DataplaneView status={status} maps={maps} />
        )}
      </main>
    </div>
  );
};

export default App;
