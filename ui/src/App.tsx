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
import { ShieldAlert, Cpu, ArrowUpRight, AlertCircle, RefreshCw } from 'lucide-react';

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
  const [connectionError, setConnectionError] = useState<string | null>(null);

  // Load live data from kwall-agent API
  const loadData = useCallback(() => {
    setIsLoading(true);
    setConnectionError(null);

    Promise.all([
      apiClient.fetchNodeStatus(),
      apiClient.fetchThreatAlerts().catch(() => []),
      apiClient.fetchPolicies().catch(() => []),
      apiClient.fetchEbpfMaps().catch(() => []),
      apiClient.fetchBlacklist().catch(() => []),
    ])
      .then(([nodeStatus, threatAlerts, pols, ebpfMaps, bl]) => {
        setStatus(nodeStatus);
        setAlerts(threatAlerts);
        setPolicies(pols);
        setMaps(ebpfMaps);
        setBlacklist(bl);
        setConnectionError(null);
      })
      .catch((err) => {
        setConnectionError(err instanceof Error ? err.message : 'Unable to connect to kwall-agent REST endpoint');
      })
      .finally(() => {
        setIsLoading(false);
      });
  }, [apiClient]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Handle entering standby mode with zero mocked numbers
  const handleEnterStandby = useCallback(() => {
    setStatus({
      nodeName: 'kwall-node-standby',
      kernelVersion: 'Linux kernel (offline mode)',
      ebpfReady: false,
      netkitActive: false,
      lsmActive: false,
      activeInterfaces: [],
      totalPackets: 0,
      totalBytes: 0,
      droppedPackets: 0,
      activeEndpoints: 0,
      enforcedPolicies: 0,
      p95LatencyUs: 0,
      p99LatencyUs: 0,
    });
    setAlerts([]);
    setPolicies([]);
    setMaps([]);
    setBlacklist([]);
    setFlows([]);
    setConnectionError(null);
    setIsLoading(false);
  }, []);

  // Real eBPF Telemetry Streaming
  useEffect(() => {
    if (!isStreaming) {
      streamer.stop();
      return;
    }

    streamer.start();

    const subscription = streamer.subscribe(
      (flow: IKwallFlowRecord) => {
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

  if (isLoading) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center text-slate-400 gap-4" role="status" aria-live="polite">
        <div className="w-12 h-12 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin" />
        <span className="text-sm font-mono tracking-wider">CONNECTING TO KWALL AGENT API...</span>
      </div>
    );
  }

  if (connectionError && !status) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center p-6 text-center">
        <div className="glass-panel p-8 max-w-lg w-full flex flex-col items-center gap-4 border border-rose-500/30 shadow-2xl">
          <div className="p-3 rounded-full bg-rose-500/15 border border-rose-500/30 text-rose-400">
            <AlertCircle className="w-8 h-8" />
          </div>
          <h2 className="text-lg font-bold text-white">kwall-agent API Unreachable</h2>
          <p className="text-xs text-slate-400 leading-relaxed">
            Could not connect to the KWALL agent endpoint at <code className="text-cyan-400 font-mono">{apiClient.getConfig().baseUrl}</code>.
            Please ensure <code className="text-slate-300 font-mono">kwall-agent</code> is running on the host.
          </p>
          <div className="text-[11px] font-mono text-rose-400 bg-slate-900/80 p-2.5 rounded-lg border border-white/5 w-full text-left truncate">
            {connectionError}
          </div>
          <div className="flex gap-3 mt-2 w-full">
            <button
              onClick={loadData}
              className="flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-cyan-400 text-slate-950 font-bold text-xs hover:bg-cyan-300 transition-all"
            >
              <RefreshCw className="w-3.5 h-3.5" /> Retry Connection
            </button>
            <button
              onClick={handleEnterStandby}
              className="flex-1 px-4 py-2 rounded-lg bg-slate-900 border border-white/20 text-slate-300 text-xs hover:border-white/40 transition-all"
            >
              Inspect Empty State
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (!status) return null;

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

                  {alerts.length === 0 ? (
                    <div className="py-6 text-center text-xs text-slate-500">
                      No security alerts recorded.
                    </div>
                  ) : (
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
                  )}
                </div>

                {/* Netkit Fastpath status */}
                <div className="glass-panel p-5 shadow-lg">
                  <div className="flex items-center gap-2 mb-3">
                    <Cpu className="w-4 h-4 text-cyan-400" />
                    <h3 className="text-sm font-bold text-white">Netkit Topology</h3>
                  </div>
                  <div className="text-xs text-slate-400 leading-relaxed">
                    Direct BPF redirect fastpath across <strong className="text-white">{status.activeInterfaces.length} interfaces</strong>.
                  </div>
                  <div className="mt-3.5 flex gap-1.5 flex-wrap">
                    {status.activeInterfaces.length === 0 ? (
                      <span className="text-xs text-slate-500">No active netkit interfaces.</span>
                    ) : (
                      status.activeInterfaces.map((iface) => (
                        <span
                          key={iface}
                          className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-900 border border-white/10 text-cyan-400"
                        >
                          {iface}
                        </span>
                      ))
                    )}
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
