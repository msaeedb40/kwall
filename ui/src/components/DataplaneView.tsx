import React from 'react';
import { Cpu, HardDrive, Network, CheckCircle2, ArrowRightLeft } from 'lucide-react';
import type { IKwallEbpfMap, IKwallNodeStatus } from '../types';

export interface IDataplaneViewProps {
  status: IKwallNodeStatus;
  maps: IKwallEbpfMap[];
}

export const DataplaneView: React.FC<IDataplaneViewProps> = ({ status, maps }) => {
  return (
    <div className="flex flex-col gap-6" role="region" aria-label="Kernel Dataplane & Netkit Diagnostics">
      {/* Kernel Subsystem Diagnostics Banner */}
      <div className="glass-panel p-6 shadow-xl">
        <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2.5">
          <Cpu className="w-5 h-5 text-cyan-400" />
          Kernel Environment & aya-bpf Runtime Subsystems
        </h2>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-4 rounded-xl bg-slate-900 border border-white/10">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-slate-400">Linux Kernel Core</span>
              <CheckCircle2 className="w-4 h-4 text-emerald-400" aria-label="Kernel Healthy" />
            </div>
            <div className="text-sm font-bold text-white font-mono">Linux 6.8.0-45</div>
            <div className="text-[11px] text-cyan-400 mt-1 font-mono">BTF (/sys/kernel/btf/vmlinux)</div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-white/10">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-slate-400">Fastpath Datapath</span>
              <CheckCircle2 className="w-4 h-4 text-emerald-400" aria-label="Netkit Ready" />
            </div>
            <div className="text-sm font-bold text-white">Netkit Direct Mode</div>
            <div className="text-[11px] text-emerald-400 mt-1">Zero-skb fastpath vs veth</div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-white/10">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-slate-400">Security Hook System</span>
              <CheckCircle2 className="w-4 h-4 text-emerald-400" aria-label="BPF LSM Enforcing" />
            </div>
            <div className="text-sm font-bold text-white">BPF LSM Enforcing</div>
            <div className="text-[11px] text-purple-400 mt-1">bprm_check_security + file_open</div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-white/10">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-slate-400">Filesystem Mounts</span>
              <CheckCircle2 className="w-4 h-4 text-emerald-400" aria-label="Filesystem Mounted" />
            </div>
            <div className="text-sm font-bold text-white">bpffs + cgroup v2</div>
            <div className="text-[11px] text-slate-400 mt-1 font-mono">/sys/fs/bpf & /sys/fs/cgroup</div>
          </div>
        </div>
      </div>

      {/* Netkit Virtual Device Architecture Card */}
      <div className="glass-panel p-6 shadow-xl">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Network className="w-4 h-4 text-cyan-400" />
              Netkit Device Topology (Linux 6.8+ Native)
            </h3>
            <span className="text-xs text-slate-400">
              Primary device attached to host TC-BPF; peer device placed inside Pod netns as eth0
            </span>
          </div>
          <span className="text-xs font-mono px-3 py-1 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
            NETKIT_MODE_L3 / REDIRECT
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 bg-slate-950 p-4 rounded-xl border border-white/10">
          {status.activeInterfaces.map((iface, idx) => (
            <div
              key={iface}
              className="p-3.5 rounded-lg bg-slate-900 border border-white/10 flex items-center justify-between"
            >
              <div className="flex items-center gap-2.5">
                <ArrowRightLeft className="w-4 h-4 text-cyan-400" />
                <div>
                  <div className="font-mono font-bold text-white text-xs">{iface}</div>
                  <div className="text-[10px] text-slate-400">
                    {iface === 'eth0' ? 'Host Physical NIC (XDP Hook)' : `Netkit Primary Peer #0${idx}`}
                  </div>
                </div>
              </div>
              <span className="text-[10px] px-2 py-0.5 rounded font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                ATTACHED
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* eBPF Kernel Maps Table */}
      <div className="glass-panel p-6 shadow-xl">
        <div className="flex items-center justify-between mb-5">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <HardDrive className="w-4 h-4 text-purple-400" />
              Pinned Kernel eBPF Maps (/sys/fs/bpf/kwall)
            </h3>
            <span className="text-xs text-slate-400">
              Aya-managed hash tables, LRU conntrack caches, and high-performance ring buffers
            </span>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-white/10 text-slate-400 font-semibold uppercase tracking-wider">
                <th className="py-2.5 px-3">Map Identifier</th>
                <th className="py-2.5 px-3">BPF Map Type</th>
                <th className="py-2.5 px-3">Capacity / Utilization</th>
                <th className="py-2.5 px-3">Key / Val Size</th>
                <th className="py-2.5 px-3">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 font-mono">
              {maps.map((m) => {
                const percent = Math.min(100, (m.currentEntries / m.maxEntries) * 100);
                return (
                  <tr key={m.name} className="hover:bg-slate-900/50 transition-colors">
                    <td className="py-3 px-3 font-bold text-cyan-400">
                      {m.name}
                    </td>
                    <td className="py-3 px-3 text-purple-400 text-xs">
                      {m.type}
                    </td>
                    <td className="py-3 px-3 min-w-[180px]">
                      <div className="flex justify-between text-[11px] mb-1">
                        <span className="text-white">{m.currentEntries.toLocaleString()}</span>
                        <span className="text-slate-500">{m.maxEntries.toLocaleString()} max</span>
                      </div>
                      <div className="h-1.5 w-full bg-slate-900 rounded-full overflow-hidden border border-white/5">
                        <div
                          className={`h-full rounded-full transition-all duration-500 ${
                            percent > 80
                              ? 'bg-rose-500'
                              : 'bg-gradient-to-r from-cyan-400 to-emerald-400'
                          }`}
                          style={{ width: `${Math.max(2, percent)}%` }}
                        />
                      </div>
                    </td>
                    <td className="py-3 px-3 text-slate-300">
                      {m.keySize}B / {m.valueSize}B
                    </td>
                    <td className="py-3 px-3 text-slate-400 font-sans text-xs">
                      {m.description}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
