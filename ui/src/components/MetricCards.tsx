import React from 'react';
import { Activity, ShieldAlert, Layers, Zap } from 'lucide-react';
import type { NodeStatus } from '../types';

interface MetricCardsProps {
  status: NodeStatus;
}

export const MetricCards: React.FC<MetricCardsProps> = ({ status }) => {
  const cards = [
    {
      title: 'eBPF Packets Processed',
      value: status.totalPackets.toLocaleString(),
      subtext: `${(status.totalBytes / (1024 * 1024 * 1024)).toFixed(2)} GB total volume`,
      icon: <Activity size={20} color="var(--accent-cyan)" />,
      glowColor: 'var(--accent-cyan-glow)',
      accentColor: 'var(--accent-cyan)',
      trend: '+14.2k/s',
    },
    {
      title: 'Packets Dropped / Filtered',
      value: status.droppedPackets.toLocaleString(),
      subtext: 'Wire-speed XDP + TC policy drops',
      icon: <ShieldAlert size={20} color="var(--accent-crimson)" />,
      glowColor: 'var(--accent-crimson-glow)',
      accentColor: 'var(--accent-crimson)',
      trend: '0.07% rate',
    },
    {
      title: 'Workload Identities',
      value: status.activeEndpoints.toString(),
      subtext: `${status.enforcedPolicies} policies compiled in KW_POLICIES`,
      icon: <Layers size={20} color="var(--accent-purple)" />,
      glowColor: 'var(--accent-purple-glow)',
      accentColor: 'var(--accent-purple)',
      trend: '100% synchronized',
    },
    {
      title: 'Kernel Dataplane Latency',
      value: `${status.p95LatencyUs} µs`,
      subtext: `P99: ${status.p99LatencyUs} µs (netkit zero-copy path)`,
      icon: <Zap size={20} color="var(--accent-green)" />,
      glowColor: 'var(--accent-green-glow)',
      accentColor: 'var(--accent-green)',
      trend: 'Ultra-low overhead',
    },
  ];

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
      gap: '18px',
      marginBottom: '28px',
    }}>
      {cards.map((c, idx) => (
        <div
          key={idx}
          className="glass-panel"
          style={{
            padding: '20px',
            position: 'relative',
            overflow: 'hidden',
          }}
        >
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginBottom: '14px',
          }}>
            <span style={{ fontSize: '13px', color: 'var(--text-secondary)', fontWeight: 500 }}>
              {c.title}
            </span>
            <div style={{
              padding: '8px',
              borderRadius: '8px',
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border-subtle)',
            }}>
              {c.icon}
            </div>
          </div>

          <div style={{ fontSize: '28px', fontWeight: 800, color: '#fff', letterSpacing: '-0.5px', marginBottom: '6px' }}>
            {c.value}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '12px' }}>
            <span style={{ color: 'var(--text-muted)' }}>{c.subtext}</span>
            <span style={{ color: c.accentColor, fontWeight: 600 }}>{c.trend}</span>
          </div>

          {/* Bottom subtle glow line */}
          <div style={{
            position: 'absolute',
            bottom: 0,
            left: 0,
            right: 0,
            height: '2px',
            background: `linear-gradient(90deg, transparent, ${c.accentColor}, transparent)`,
            opacity: 0.6,
          }} />
        </div>
      ))}
    </div>
  );
};
