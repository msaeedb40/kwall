import React from 'react';
import { Activity, ShieldAlert, Layers, Zap } from 'lucide-react';
import type { IKwallNodeStatus } from '../types';

export interface IMetricCardsProps {
  status: IKwallNodeStatus;
}

export const MetricCards: React.FC<IMetricCardsProps> = ({ status }) => {
  const cards = [
    {
      title: 'eBPF Packets Processed',
      value: status.totalPackets.toLocaleString(),
      subtext: `${(status.totalBytes / (1024 * 1024 * 1024)).toFixed(2)} GB total volume`,
      icon: <Activity className="w-5 h-5 text-cyan-400" />,
      borderGlow: 'hover:border-cyan-500/50 hover:shadow-cyan-500/10',
      badgeColor: 'text-cyan-400 bg-cyan-500/10',
      trend: '+18.4k/s',
    },
    {
      title: 'Packets Dropped / Filtered',
      value: status.droppedPackets.toLocaleString(),
      subtext: 'Wire-speed XDP + TC policy drops',
      icon: <ShieldAlert className="w-5 h-5 text-rose-500" />,
      borderGlow: 'hover:border-rose-500/50 hover:shadow-rose-500/10',
      badgeColor: 'text-rose-400 bg-rose-500/10',
      trend: `${((status.droppedPackets / Math.max(1, status.totalPackets)) * 100).toFixed(3)}% rate`,
    },
    {
      title: 'Workload Identities',
      value: status.activeEndpoints.toString(),
      subtext: `${status.enforcedPolicies} policies active in KW_POLICIES`,
      icon: <Layers className="w-5 h-5 text-purple-400" />,
      borderGlow: 'hover:border-purple-500/50 hover:shadow-purple-500/10',
      badgeColor: 'text-purple-400 bg-purple-500/10',
      trend: '100% sync',
    },
    {
      title: 'Dataplane Fastpath Latency',
      value: `${status.p95LatencyUs} µs`,
      subtext: `p99: ${status.p99LatencyUs} µs via Linux netkit`,
      icon: <Zap className="w-5 h-5 text-emerald-400" />,
      borderGlow: 'hover:border-emerald-500/50 hover:shadow-emerald-500/10',
      badgeColor: 'text-emerald-400 bg-emerald-500/10',
      trend: 'Sub-µs fastpath',
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map((c) => (
        <div
          key={c.title}
          className={`glass-panel p-5 transition-all duration-300 hover:-translate-y-0.5 shadow-lg ${c.borderGlow}`}
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">{c.title}</span>
            <div className="p-2 rounded-lg bg-slate-900 border border-white/10">
              {c.icon}
            </div>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <div className="text-2xl font-black text-white font-mono tracking-tight">
              {c.value}
            </div>
            <span className={`text-[11px] font-bold px-2 py-0.5 rounded-full ${c.badgeColor}`}>
              {c.trend}
            </span>
          </div>
          <div className="mt-2 text-xs text-slate-400 font-mono">
            {c.subtext}
          </div>
        </div>
      ))}
    </div>
  );
};
