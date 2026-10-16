import React, { useState } from 'react';
import { ShieldAlert, AlertTriangle, Ban, CheckCircle2, ShieldCheck, Flame, Plus, Trash2 } from 'lucide-react';
import type { IKwallSecurityAlert, IKwallBlacklistEntry } from '../types';

export interface IThreatsViewProps {
  alerts: IKwallSecurityAlert[];
  blacklist: IKwallBlacklistEntry[];
  onAddBlacklist: (ip: string, reason: string) => Promise<void>;
  onRemoveBlacklist: (ip: string) => Promise<void>;
}

export const ThreatsView: React.FC<IThreatsViewProps> = ({
  alerts,
  blacklist,
  onAddBlacklist,
  onRemoveBlacklist,
}) => {
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [newIp, setNewIp] = useState('');
  const [newReason, setNewReason] = useState('');
  const [showAddModal, setShowAddModal] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const filteredAlerts = alerts.filter(
    (a) => filterSeverity === 'ALL' || a.severity.toUpperCase() === filterSeverity
  );

  const handleFormSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIp.trim()) return;
    setIsSubmitting(true);
    try {
      await onAddBlacklist(newIp.trim(), newReason.trim() || 'Manual Operator Ban');
      setNewIp('');
      setNewReason('');
      setShowAddModal(false);
    } finally {
      setIsSubmitting(false);
    }
  };

  const getSeverityBadge = (severity: IKwallSecurityAlert['severity']) => {
    const badgeColors: Record<string, string> = {
      Critical: 'bg-rose-500/15 text-rose-400 border-rose-500/40',
      High: 'bg-orange-500/15 text-orange-400 border-orange-500/40',
      Medium: 'bg-amber-500/15 text-amber-400 border-amber-500/40',
      Low: 'bg-blue-500/15 text-blue-400 border-blue-500/40',
      Info: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40',
    };
    return (
      <span className={`px-2 py-0.5 rounded text-[10px] font-extrabold uppercase tracking-wider border ${badgeColors[severity] || badgeColors.Info}`}>
        {severity}
      </span>
    );
  };

  return (
    <div className="flex flex-col gap-6">
      {/* Top Banner Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="glass-panel p-5 border-l-4 border-l-rose-500 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400">eBPF SYN Flood Mitigator</span>
            <Flame className="w-5 h-5 text-rose-500" />
          </div>
          <div className="text-xl font-bold text-white mt-2">
            Active (SYN Cookies + XDP)
          </div>
          <div className="text-xs text-slate-400 mt-1">
            Threshold: 10,000 pps / IP • Hardware-speed drop
          </div>
        </div>

        <div className="glass-panel p-5 border-l-4 border-l-amber-500 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400">BPF LSM Process Guard</span>
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
          </div>
          <div className="text-xl font-bold text-white mt-2">
            Zero-Trust Enforced
          </div>
          <div className="text-xs text-slate-400 mt-1">
            Hook: bprm_check_security • Blake3 SHA integrity
          </div>
        </div>

        <div className="glass-panel p-5 border-l-4 border-l-cyan-400 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400">XDP Blacklist Map Size</span>
            <Ban className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="text-xl font-bold text-white mt-2 font-mono">
            {blacklist.length} Banned CIDRs
          </div>
          <div className="text-xs text-slate-400 mt-1">
            Kernel Map: KW_IP_BLACKLIST (65,536 max entries)
          </div>
        </div>
      </div>

      {/* Main Grid: Alerts + Blacklist Manager */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Security Alerts List */}
        <div className="glass-panel p-6 shadow-xl">
          <div className="flex flex-wrap items-center justify-between gap-3 mb-5">
            <div className="flex items-center gap-2.5">
              <ShieldAlert className="w-5 h-5 text-rose-500" />
              <h3 className="text-base font-bold text-white">Kernel Security & LSM Alerts</h3>
            </div>
            <div className="flex gap-1 bg-slate-900 border border-white/10 p-0.5 rounded-lg text-xs">
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setFilterSeverity(sev)}
                  className={`px-2.5 py-1 rounded text-xs font-semibold transition-all ${
                    filterSeverity === sev ? 'bg-cyan-500 text-slate-950 font-bold' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          <div className="flex flex-col gap-3">
            {filteredAlerts.length === 0 ? (
              <div className="py-12 text-center text-slate-500 text-xs">
                No active threats detected.
              </div>
            ) : (
              filteredAlerts.map((alert) => (
                <div
                  key={alert.id}
                  className="p-4 rounded-xl bg-slate-900/80 border border-white/10 flex flex-col gap-2.5 transition-all hover:border-white/20"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      {getSeverityBadge(alert.severity)}
                      <span className="font-bold text-white text-xs">{alert.type}</span>
                    </div>
                    <span className="text-xs font-mono text-slate-500">{alert.timestamp}</span>
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed">
                    {alert.description}
                  </p>

                  <div className="flex flex-wrap items-center justify-between pt-2 border-t border-white/5 text-xs">
                    <div className="flex gap-3 text-slate-400">
                      <span>Target: <strong className="text-white">{alert.podName}</strong></span>
                      <span>Source IP: <strong className="text-white">{alert.sourceIp}</strong></span>
                    </div>
                    <div>
                      {alert.blocked ? (
                        <span className="text-emerald-400 flex items-center gap-1 font-semibold text-xs">
                          <CheckCircle2 className="w-3.5 h-3.5" /> Mitigated by eBPF
                        </span>
                      ) : (
                        <span className="text-amber-400 flex items-center gap-1 font-semibold text-xs">
                          <AlertTriangle className="w-3.5 h-3.5" /> Monitoring
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* XDP Early Drop Blacklist Manager */}
        <div className="glass-panel p-6 shadow-xl">
          <div className="flex items-center justify-between mb-5">
            <div className="flex items-center gap-2.5">
              <Ban className="w-5 h-5 text-cyan-400" />
              <div>
                <h3 className="text-base font-bold text-white">XDP Early Drop Blacklist</h3>
                <span className="text-[11px] text-slate-400 font-mono">Synchronized to bpf_map_lookup_elem(&kw_ip_blacklist)</span>
              </div>
            </div>
            <button
              onClick={() => setShowAddModal(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-cyan-400 bg-cyan-500/10 text-cyan-400 text-xs font-semibold hover:bg-cyan-500/20 transition-all"
            >
              <Plus className="w-3.5 h-3.5" /> Ban IP
            </button>
          </div>

          {showAddModal && (
            <form onSubmit={handleFormSubmit} className="mb-4 p-4 rounded-xl bg-slate-900 border border-cyan-400 flex flex-col gap-3">
              <div className="text-xs font-bold text-white">Add IPv4/CIDR to XDP Blacklist</div>
              <div className="flex flex-col sm:flex-row gap-2">
                <input
                  type="text"
                  placeholder="IPv4 (e.g. 198.51.100.5)"
                  value={newIp}
                  onChange={(e) => setNewIp(e.target.value)}
                  className="flex-1 bg-slate-950 border border-white/20 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400"
                  required
                />
                <input
                  type="text"
                  placeholder="Reason / CVE tag"
                  value={newReason}
                  onChange={(e) => setNewReason(e.target.value)}
                  className="flex-1 bg-slate-950 border border-white/20 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400"
                />
              </div>
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-3 py-1.5 rounded-lg border border-white/20 text-slate-300 text-xs hover:border-white/40"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-1.5 rounded-lg bg-cyan-400 text-slate-950 font-bold text-xs hover:bg-cyan-300 disabled:opacity-50"
                >
                  {isSubmitting ? 'Committing...' : 'Commit to eBPF Map'}
                </button>
              </div>
            </form>
          )}

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse font-mono">
              <thead>
                <tr className="border-b border-white/10 text-slate-400 font-sans font-semibold">
                  <th className="py-2.5 px-3">Banned Address</th>
                  <th className="py-2.5 px-3">Reason</th>
                  <th className="py-2.5 px-3">Drops</th>
                  <th className="py-2.5 px-3 text-right font-sans">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {blacklist.map((item) => (
                  <tr key={item.ip} className="hover:bg-slate-900/50 transition-colors">
                    <td className="py-2.5 px-3 font-bold text-rose-400">
                      {item.ip}
                    </td>
                    <td className="py-2.5 px-3 text-slate-300 font-sans">
                      {item.reason}
                    </td>
                    <td className="py-2.5 px-3 text-slate-400">
                      {item.packetsDropped.toLocaleString()}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <button
                        onClick={() => onRemoveBlacklist(item.ip)}
                        title="Remove from XDP Map"
                        className="p-1 rounded text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
