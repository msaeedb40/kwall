import React from 'react';
import { Shield, Cpu, Network, Play, Pause, Radio } from 'lucide-react';
import type { IKwallNodeStatus, StreamConnectionStatus } from '../types';

export interface IHeaderProps {
  status: IKwallNodeStatus;
  streamStatus: StreamConnectionStatus;
  isStreaming: boolean;
  onToggleStreaming: () => void;
  activeTab: string;
  onSelectTab: (tab: string) => void;
}

export const Header: React.FC<IHeaderProps> = ({
  status,
  streamStatus,
  isStreaming,
  onToggleStreaming,
  activeTab,
  onSelectTab,
}) => {
  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'flows', label: 'eBPF Flow Stream' },
    { id: 'threats', label: 'Threat Center & DDoS' },
    { id: 'policies', label: 'Policy Engine' },
    { id: 'dataplane', label: 'Kernel Maps & Netkit' },
  ];

  return (
    <header className="sticky top-0 z-50 px-6 backdrop-blur-xl bg-slate-950/85 border-b border-white/10">
      {/* Top Banner */}
      <div className="flex items-center justify-between h-16 border-b border-white/10">
        <div className="flex items-center gap-4">
          <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-emerald-500/20 border border-cyan-400/40 shadow-lg shadow-cyan-500/20">
            <Shield className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-xl font-extrabold tracking-tight text-white">KWALL</h1>
              <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 uppercase tracking-wider">
                eBPF + Netkit
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Kubernetes Dataplane & Runtime Security Platform
            </p>
          </div>
        </div>

        {/* Node Status & Stream Controls */}
        <div className="flex items-center gap-4">
          <div className="hidden md:flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-slate-900 border border-white/10 text-xs">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <span className="text-slate-400">Node:</span>
            <span className="font-mono font-semibold text-white">{status.nodeName}</span>
            <span className="pulse-dot green" title="Kernel compatible and eBPF active" />
          </div>

          <div className="hidden sm:flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-slate-900 border border-white/10 text-xs">
            <Network className="w-4 h-4 text-emerald-400" />
            <span className="text-slate-400">Netkit:</span>
            <span className="font-semibold text-emerald-400">
              {status.netkitActive ? 'ACTIVE' : 'STANDBY'}
            </span>
          </div>

          <div className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-slate-900 border border-white/10 text-xs">
            <Radio className={`w-3.5 h-3.5 ${streamStatus === 'STREAMING' ? 'text-emerald-400 animate-pulse' : 'text-amber-400'}`} />
            <span className="font-mono text-slate-300">{streamStatus}</span>
          </div>

          <button
            onClick={onToggleStreaming}
            id="toggle-stream-btn"
            className={`flex items-center gap-2 px-4 py-1.5 rounded-lg text-xs font-semibold transition-all border ${
              isStreaming
                ? 'bg-cyan-500/15 border-cyan-400 text-cyan-400 shadow-lg shadow-cyan-500/20'
                : 'bg-slate-900 border-white/20 text-slate-300 hover:border-white/40'
            }`}
          >
            {isStreaming ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
            {isStreaming ? 'Live Stream' : 'Paused'}
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <nav className="flex gap-2 py-2 overflow-x-auto">
        {tabs.map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => onSelectTab(tab.id)}
              id={`tab-${tab.id}`}
              className={`px-4 py-2 rounded-lg text-xs font-medium transition-all ${
                isActive
                  ? 'bg-cyan-500/15 text-cyan-400 font-semibold border border-cyan-400/40 shadow-sm shadow-cyan-500/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
              }`}
            >
              {tab.label}
            </button>
          );
        })}
      </nav>
    </header>
  );
};
