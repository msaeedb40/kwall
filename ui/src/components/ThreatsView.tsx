import React, { useState } from 'react';
import { ShieldAlert, AlertTriangle, Ban, CheckCircle2, ShieldCheck, Flame, Plus, Trash2 } from 'lucide-react';
import type { SecurityAlert } from '../types';

interface ThreatsViewProps {
  alerts: SecurityAlert[];
}

export const ThreatsView: React.FC<ThreatsViewProps> = ({ alerts }) => {
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [blacklist, setBlacklist] = useState<Array<{ ip: string; reason: string; timestamp: string; packetsDropped: number }>>([
    { ip: '203.0.113.89', reason: 'SYN Flood (>10k pps)', timestamp: '10:44:50', packetsDropped: 14208 },
    { ip: '198.51.100.14', reason: 'Port Scan (28 ports/200ms)', timestamp: '10:31:12', packetsDropped: 894 },
    { ip: '192.0.2.77', reason: 'Repeated Policy Deny Violations', timestamp: '09:55:04', packetsDropped: 312 },
  ]);
  const [newIp, setNewIp] = useState('');
  const [newReason, setNewReason] = useState('');
  const [showAddModal, setShowAddModal] = useState(false);

  const filteredAlerts = alerts.filter(
    (a) => filterSeverity === 'ALL' || a.severity.toUpperCase() === filterSeverity
  );

  const handleAddBlacklist = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIp.trim()) return;
    setBlacklist([
      {
        ip: newIp.trim(),
        reason: newReason.trim() || 'Manual Operator Ban',
        timestamp: new Date().toLocaleTimeString(),
        packetsDropped: 0,
      },
      ...blacklist,
    ]);
    setNewIp('');
    setNewReason('');
    setShowAddModal(false);
  };

  const handleRemoveBlacklist = (ip: string) => {
    setBlacklist(blacklist.filter((item) => item.ip !== ip));
  };

  const getSeverityBadge = (severity: SecurityAlert['severity']) => {
    const styles: Record<string, { bg: string; text: string; border: string }> = {
      Critical: { bg: 'rgba(239, 68, 68, 0.15)', text: '#ef4444', border: '#ef4444' },
      High: { bg: 'rgba(249, 115, 22, 0.15)', text: '#f97316', border: '#f97316' },
      Medium: { bg: 'rgba(245, 158, 11, 0.15)', text: '#f59e0b', border: '#f59e0b' },
      Low: { bg: 'rgba(59, 130, 246, 0.15)', text: '#3b82f6', border: '#3b82f6' },
      Info: { bg: 'rgba(16, 185, 129, 0.15)', text: '#10b981', border: '#10b981' },
    };
    const s = styles[severity] || styles.Info;
    return (
      <span
        style={{
          padding: '2px 8px',
          borderRadius: '4px',
          fontSize: '11px',
          fontWeight: 700,
          background: s.bg,
          color: s.text,
          border: `1px solid ${s.border}`,
          textTransform: 'uppercase',
          letterSpacing: '0.5px',
        }}
      >
        {severity}
      </span>
    );
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Banner Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
        <div className="glass-panel" style={{ padding: '20px', borderLeft: '4px solid var(--accent-crimson)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>eBPF SYN Flood Mitigator</span>
            <Flame size={18} color="var(--accent-crimson)" />
          </div>
          <div style={{ fontSize: '24px', fontWeight: 800, color: '#fff', marginTop: '10px' }}>
            Active (SYN Cookies + XDP)
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
            Threshold: 10,000 pps / IP • Hardware-speed drop
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '20px', borderLeft: '4px solid var(--accent-amber)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>BPF LSM Process Guard</span>
            <ShieldCheck size={18} color="var(--accent-emerald)" />
          </div>
          <div style={{ fontSize: '24px', fontWeight: 800, color: '#fff', marginTop: '10px' }}>
            Zero-Trust Enforced
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
            Hook: bprm_check_security • Blake3 SHA integrity
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '20px', borderLeft: '4px solid var(--accent-cyan)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>XDP Blacklist Map Size</span>
            <Ban size={18} color="var(--accent-cyan)" />
          </div>
          <div style={{ fontSize: '24px', fontWeight: 800, color: '#fff', marginTop: '10px' }}>
            {blacklist.length} Banned CIDRs
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
            Kernel Map: KW_IP_BLACKLIST (65,536 max entries)
          </div>
        </div>
      </div>

      {/* Main Grid: Alerts + Blacklist Manager */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(480px, 1fr))', gap: '24px' }}>
        {/* Security Alerts List */}
        <div className="glass-panel" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <ShieldAlert size={20} color="var(--accent-crimson)" />
              <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#fff' }}>Kernel Security & LSM Alerts</h3>
            </div>
            <div style={{ display: 'flex', gap: '6px' }}>
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setFilterSeverity(sev)}
                  style={{
                    padding: '4px 10px',
                    borderRadius: '6px',
                    fontSize: '11px',
                    fontWeight: 600,
                    border: 'none',
                    background: filterSeverity === sev ? 'var(--accent-cyan)' : 'var(--bg-secondary)',
                    color: filterSeverity === sev ? '#000' : 'var(--text-secondary)',
                    cursor: 'pointer',
                  }}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {filteredAlerts.length === 0 ? (
              <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
                No active threats matching severity filter.
              </div>
            ) : (
              filteredAlerts.map((alert) => (
                <div
                  key={alert.id}
                  style={{
                    padding: '16px',
                    borderRadius: '8px',
                    background: 'var(--bg-secondary)',
                    border: '1px solid var(--border-subtle)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '8px',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      {getSeverityBadge(alert.severity)}
                      <span style={{ fontWeight: 700, color: '#fff', fontSize: '14px' }}>{alert.type}</span>
                    </div>
                    <span style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                      {alert.timestamp}
                    </span>
                  </div>

                  <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                    {alert.description}
                  </p>

                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    paddingTop: '8px',
                    borderTop: '1px solid var(--border-subtle)',
                    fontSize: '12px',
                  }}>
                    <div style={{ display: 'flex', gap: '14px', color: 'var(--text-muted)' }}>
                      <span>Target: <strong style={{ color: '#fff' }}>{alert.podName}</strong></span>
                      <span>Source IP: <strong style={{ color: '#fff' }}>{alert.sourceIp}</strong></span>
                    </div>
                    <div>
                      {alert.blocked ? (
                        <span style={{ color: 'var(--accent-emerald)', display: 'flex', alignItems: 'center', gap: '4px', fontWeight: 600 }}>
                          <CheckCircle2 size={14} /> Mitigated by eBPF
                        </span>
                      ) : (
                        <span style={{ color: 'var(--accent-amber)', display: 'flex', alignItems: 'center', gap: '4px', fontWeight: 600 }}>
                          <AlertTriangle size={14} /> Monitoring
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
        <div className="glass-panel" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Ban size={20} color="var(--accent-cyan)" />
              <div>
                <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#fff' }}>XDP Early Drop Blacklist</h3>
                <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Synchronized to bpf_map_lookup_elem(&kw_ip_blacklist)</span>
              </div>
            </div>
            <button
              onClick={() => setShowAddModal(true)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '6px 12px',
                borderRadius: '6px',
                border: '1px solid var(--accent-cyan)',
                background: 'rgba(0, 240, 255, 0.1)',
                color: 'var(--accent-cyan)',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              <Plus size={14} /> Ban IP
            </button>
          </div>

          {showAddModal && (
            <form
              onSubmit={handleAddBlacklist}
              style={{
                marginBottom: '16px',
                padding: '16px',
                borderRadius: '8px',
                background: 'var(--bg-tertiary)',
                border: '1px solid var(--accent-cyan)',
                display: 'flex',
                flexDirection: 'column',
                gap: '10px',
              }}
            >
              <div style={{ fontSize: '13px', fontWeight: 700, color: '#fff' }}>Add IP to XDP Blacklist</div>
              <div style={{ display: 'flex', gap: '10px' }}>
                <input
                  type="text"
                  placeholder="IPv4 or CIDR (e.g. 198.51.100.5)"
                  value={newIp}
                  onChange={(e) => setNewIp(e.target.value)}
                  style={{
                    flex: 1,
                    background: 'var(--bg-primary)',
                    border: '1px solid var(--border-medium)',
                    color: '#fff',
                    padding: '8px 12px',
                    borderRadius: '6px',
                    fontSize: '13px',
                  }}
                  required
                />
                <input
                  type="text"
                  placeholder="Reason / CVE tag"
                  value={newReason}
                  onChange={(e) => setNewReason(e.target.value)}
                  style={{
                    flex: 1,
                    background: 'var(--bg-primary)',
                    border: '1px solid var(--border-medium)',
                    color: '#fff',
                    padding: '8px 12px',
                    borderRadius: '6px',
                    fontSize: '13px',
                  }}
                />
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  style={{
                    padding: '6px 12px',
                    background: 'transparent',
                    border: '1px solid var(--border-medium)',
                    color: 'var(--text-secondary)',
                    borderRadius: '6px',
                    fontSize: '12px',
                    cursor: 'pointer',
                  }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  style={{
                    padding: '6px 14px',
                    background: 'var(--accent-cyan)',
                    border: 'none',
                    color: '#000',
                    fontWeight: 700,
                    borderRadius: '6px',
                    fontSize: '12px',
                    cursor: 'pointer',
                  }}
                >
                  Commit to eBPF Map
                </button>
              </div>
            </form>
          )}

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
                  <th style={{ padding: '10px 8px' }}>Banned Address</th>
                  <th style={{ padding: '10px 8px' }}>Reason</th>
                  <th style={{ padding: '10px 8px' }}>Blocked Packets</th>
                  <th style={{ padding: '10px 8px', textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {blacklist.map((item) => (
                  <tr key={item.ip} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                    <td style={{ padding: '12px 8px', fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--accent-crimson)' }}>
                      {item.ip}
                    </td>
                    <td style={{ padding: '12px 8px', color: 'var(--text-secondary)' }}>
                      {item.reason}
                    </td>
                    <td style={{ padding: '12px 8px', fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                      {item.packetsDropped.toLocaleString()}
                    </td>
                    <td style={{ padding: '12px 8px', textAlign: 'right' }}>
                      <button
                        onClick={() => handleRemoveBlacklist(item.ip)}
                        title="Remove from XDP Map"
                        style={{
                          background: 'transparent',
                          border: 'none',
                          color: 'var(--text-muted)',
                          cursor: 'pointer',
                          padding: '4px',
                          borderRadius: '4px',
                          transition: 'color 0.15s',
                        }}
                        onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--accent-crimson)')}
                        onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--text-muted)')}
                      >
                        <Trash2 size={16} />
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
