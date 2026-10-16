import React, { useState } from 'react';
import { Search, ArrowUpRight, ArrowDownLeft, CheckCircle2, XCircle, Info, ChevronRight } from 'lucide-react';
import type { IKwallFlowRecord, FlowVerdict } from '../types';

export interface IFlowsTableProps {
  flows: IKwallFlowRecord[];
}

export const FlowsTable: React.FC<IFlowsTableProps> = ({ flows }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [verdictFilter, setVerdictFilter] = useState<'ALL' | FlowVerdict>('ALL');
  const [selectedFlow, setSelectedFlow] = useState<IKwallFlowRecord | null>(null);

  const filteredFlows = flows.filter((f) => {
    const matchesSearch =
      f.srcPod.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.dstPod.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.srcIp.includes(searchTerm) ||
      f.dstIp.includes(searchTerm) ||
      f.dstPort.toString().includes(searchTerm);

    const matchesVerdict = verdictFilter === 'ALL' || f.verdict === verdictFilter;
    return matchesSearch && matchesVerdict;
  });

  return (
    <div className="glass-panel p-6 shadow-xl">
      {/* Controls Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 mb-5">
        <div className="flex items-center gap-3">
          <h2 className="text-lg font-bold text-white tracking-tight">
            Live Kernel Flow Telemetry
          </h2>
          <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-white/10">
            {filteredFlows.length} flows captured
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Search bar */}
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search pod, IP or port..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-slate-900 border border-white/10 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 w-52 md:w-64"
            />
          </div>

          {/* Verdict Filter pills */}
          <div className="flex gap-1 p-0.5 rounded-lg bg-slate-900 border border-white/10 text-xs">
            {(['ALL', 'PASS', 'DROP'] as const).map((v) => (
              <button
                key={v}
                onClick={() => setVerdictFilter(v)}
                className={`px-3 py-1 rounded-md text-xs font-semibold transition-all ${
                  verdictFilter === v
                    ? v === 'PASS'
                      ? 'bg-emerald-500 text-slate-950 font-bold'
                      : v === 'DROP'
                      ? 'bg-rose-500 text-white font-bold'
                      : 'bg-cyan-500 text-slate-950 font-bold'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {v}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Main Table View */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-white/10 text-slate-400 font-semibold uppercase tracking-wider">
              <th className="py-2.5 px-3">Time</th>
              <th className="py-2.5 px-3">Dir</th>
              <th className="py-2.5 px-3">Source (ID / Pod)</th>
              <th className="py-2.5 px-3">Destination (ID / Pod)</th>
              <th className="py-2.5 px-3">Port / Proto</th>
              <th className="py-2.5 px-3">Volume</th>
              <th className="py-2.5 px-3">Verdict</th>
              <th className="py-2.5 px-3 text-right">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5 font-mono">
            {filteredFlows.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-8 text-center text-slate-500 font-sans">
                  No eBPF flows captured matching search criteria.
                </td>
              </tr>
            ) : (
              filteredFlows.map((flow) => {
                const isPass = flow.verdict === 'PASS';
                const isSelected = selectedFlow?.id === flow.id;
                return (
                  <tr
                    key={flow.id}
                    onClick={() => setSelectedFlow(flow)}
                    className={`cursor-pointer transition-colors ${
                      isSelected ? 'bg-cyan-500/10' : 'hover:bg-slate-900/60'
                    }`}
                  >
                    <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                      {flow.timestamp}
                    </td>
                    <td className="py-2.5 px-3">
                      {flow.direction === 'INGRESS' ? (
                        <span className="flex items-center gap-1 text-cyan-400 text-[11px] font-bold">
                          <ArrowDownLeft className="w-3.5 h-3.5" /> IN
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 text-purple-400 text-[11px] font-bold">
                          <ArrowUpRight className="w-3.5 h-3.5" /> OUT
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-3">
                      <div className="font-semibold text-white truncate max-w-[170px]" title={flow.srcPod}>
                        {flow.srcPod}
                      </div>
                      <div className="text-[11px] text-slate-400">
                        {flow.srcIp} <span className="text-cyan-400 font-bold">[{flow.srcIdentity}]</span>
                      </div>
                    </td>
                    <td className="py-2.5 px-3">
                      <div className="font-semibold text-white truncate max-w-[170px]" title={flow.dstPod}>
                        {flow.dstPod}
                      </div>
                      <div className="text-[11px] text-slate-400">
                        {flow.dstIp} <span className="text-cyan-400 font-bold">[{flow.dstIdentity}]</span>
                      </div>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="px-2 py-0.5 rounded bg-slate-900 border border-white/10 text-white font-semibold">
                        :{flow.dstPort}
                      </span>{' '}
                      <span className="text-slate-400 text-[11px]">{flow.protocol}</span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-300 whitespace-nowrap">
                      {flow.bytes} B <span className="text-slate-500 text-[10px]">({flow.packets} pkts)</span>
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span
                        className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold uppercase tracking-wide border ${
                          isPass
                            ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                            : 'bg-rose-500/15 text-rose-400 border-rose-500/30'
                        }`}
                      >
                        {isPass ? <CheckCircle2 className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
                        {flow.verdict}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <ChevronRight className="w-4 h-4 text-slate-500 inline-block" />
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Detail Drawer */}
      {selectedFlow && (
        <div className="mt-6 p-4 rounded-xl bg-slate-950/80 border border-cyan-500/30 font-mono text-xs shadow-2xl">
          <div className="flex items-center justify-between pb-3 border-b border-white/10 mb-3">
            <div className="flex items-center gap-2">
              <Info className="w-4 h-4 text-cyan-400" />
              <span className="font-bold text-white font-sans text-sm">
                eBPF Packet Ringbuffer Inspection [{selectedFlow.id}]
              </span>
            </div>
            <button
              onClick={() => setSelectedFlow(null)}
              className="text-slate-400 hover:text-white font-sans text-xs"
            >
              Close
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <div className="text-slate-400 text-[11px]">Source Endpoint:</div>
              <div className="text-white font-semibold">{selectedFlow.srcPod} ({selectedFlow.srcIp})</div>
              <div className="text-slate-400 text-[11px] mt-2">Destination Endpoint:</div>
              <div className="text-white font-semibold">{selectedFlow.dstPod} ({selectedFlow.dstIp}:{selectedFlow.dstPort})</div>
            </div>
            <div>
              <div className="text-slate-400 text-[11px]">Aya Ringbuffer Verdict:</div>
              <div className={selectedFlow.verdict === 'PASS' ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold'}>
                {selectedFlow.verdict} {selectedFlow.dropReason ? `— ${selectedFlow.dropReason}` : ''}
              </div>
              <div className="text-slate-400 text-[11px] mt-2">Namespace & Payload:</div>
              <div className="text-slate-300">{selectedFlow.namespace} • {selectedFlow.bytes} Bytes ({selectedFlow.packets} packets)</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
