import React from 'react';
import { Cpu, HardDrive, Network, CheckCircle2, ArrowRightLeft } from 'lucide-react';
import type { EbpfMapInfo, NodeStatus } from '../types';

interface DataplaneViewProps {
  status: NodeStatus;
  maps: EbpfMapInfo[];
}

export const DataplaneView: React.FC<DataplaneViewProps> = ({ status, maps }) => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Kernel Subsystem Diagnostics Banner */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <h2 style={{ fontSize: '18px', fontWeight: 800, color: '#fff', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Cpu size={22} color="var(--accent-cyan)" />
          Kernel Environment & aya-bpf Runtime Subsystems
        </h2>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px' }}>
          <div style={{ padding: '16px', borderRadius: '8px', background: 'var(--bg-secondary)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
              <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Linux Kernel Core</span>
              <CheckCircle2 size={16} color="var(--accent-emerald)" />
            </div>
            <div style={{ fontSize: '14px', fontWeight: 700, color: '#fff' }}>Linux 6.8.0-45</div>
            <div style={{ fontSize: '11px', color: 'var(--accent-cyan)', marginTop: '4px' }}>BTF Enabled (/sys/kernel/btf/vmlinux)</div>
          </div>

          <div style={{ padding: '16px', borderRadius: '8px', background: 'var(--bg-secondary)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
              <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Fastpath Datapath</span>
              <CheckCircle2 size={16} color="var(--accent-emerald)" />
            </div>
            <div style={{ fontSize: '14px', fontWeight: 700, color: '#fff' }}>Netkit Direct Mode</div>
            <div style={{ fontSize: '11px', color: 'var(--accent-emerald)', marginTop: '4px' }}>Zero-skb overhead vs legacy veth</div>
          </div>

          <div style={{ padding: '16px', borderRadius: '8px', background: 'var(--bg-secondary)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
              <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Security Hook System</span>
              <CheckCircle2 size={16} color="var(--accent-emerald)" />
            </div>
            <div style={{ fontSize: '14px', fontWeight: 700, color: '#fff' }}>BPF LSM Enforcing</div>
            <div style={{ fontSize: '11px', color: 'var(--accent-purple)', marginTop: '4px' }}>bprm_check_security + file_open</div>
          </div>

          <div style={{ padding: '16px', borderRadius: '8px', background: 'var(--bg-secondary)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
              <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Filesystem Mounts</span>
              <CheckCircle2 size={16} color="var(--accent-emerald)" />
            </div>
            <div style={{ fontSize: '14px', fontWeight: 700, color: '#fff' }}>bpffs + cgroup v2</div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>Mounted at /sys/fs/bpf & /sys/fs/cgroup</div>
          </div>
        </div>
      </div>

      {/* Netkit Virtual Device Architecture Card */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
          <div>
            <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Network size={18} color="var(--accent-cyan)" />
              Netkit Device Topology (Linux 6.8+ Native)
            </h3>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Primary device attached to host TC-BPF; peer device placed inside Pod netns as eth0
            </span>
          </div>
          <span style={{
            fontSize: '11px',
            fontFamily: 'var(--font-mono)',
            padding: '4px 10px',
            borderRadius: '6px',
            background: 'rgba(0, 240, 255, 0.12)',
            color: 'var(--accent-cyan)',
            border: '1px solid var(--accent-cyan)',
          }}>
            NETKIT_MODE_L3 / REDIRECT
          </span>
        </div>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: '12px',
          background: 'var(--bg-primary)',
          padding: '20px',
          borderRadius: '8px',
          border: '1px solid var(--border-subtle)',
        }}>
          {status.activeInterfaces.map((iface, idx) => (
            <div
              key={iface}
              style={{
                padding: '14px',
                borderRadius: '6px',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border-subtle)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <ArrowRightLeft size={16} color="var(--accent-cyan)" />
                <div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#fff', fontSize: '13px' }}>
                    {iface}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    {iface === 'eth0' ? 'Host Physical NIC (XDP Hook)' : `Netkit Primary Peer #0${idx}`}
                  </div>
                </div>
              </div>
              <span style={{
                fontSize: '11px',
                padding: '2px 8px',
                borderRadius: '4px',
                background: 'rgba(16, 185, 129, 0.15)',
                color: 'var(--accent-emerald)',
                fontWeight: 600,
              }}>
                ATTACHED
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* eBPF Kernel Maps Table */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
          <div>
            <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <HardDrive size={18} color="var(--accent-purple)" />
              Pinned Kernel eBPF Maps (/sys/fs/bpf/kwall)
            </h3>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Aya-managed hash tables, LRU conntrack caches, and high-performance ring buffers
            </span>
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
                <th style={{ padding: '10px 12px' }}>Map Identifier</th>
                <th style={{ padding: '10px 12px' }}>BPF Map Type</th>
                <th style={{ padding: '10px 12px' }}>Capacity / Utilization</th>
                <th style={{ padding: '10px 12px' }}>Key / Value Sizes</th>
                <th style={{ padding: '10px 12px' }}>Description</th>
              </tr>
            </thead>
            <tbody>
              {maps.map((m) => {
                const percent = Math.min(100, (m.currentEntries / m.maxEntries) * 100);
                return (
                  <tr key={m.name} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                    <td style={{ padding: '14px 12px', fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--accent-cyan)' }}>
                      {m.name}
                    </td>
                    <td style={{ padding: '14px 12px', fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--accent-purple)' }}>
                      {m.type}
                    </td>
                    <td style={{ padding: '14px 12px', minWidth: '180px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', marginBottom: '4px' }}>
                        <span style={{ color: '#fff' }}>{m.currentEntries.toLocaleString()}</span>
                        <span style={{ color: 'var(--text-muted)' }}>{m.maxEntries.toLocaleString()} max</span>
                      </div>
                      <div style={{ height: '6px', width: '100%', background: 'var(--bg-tertiary)', borderRadius: '3px', overflow: 'hidden' }}>
                        <div
                          style={{
                            height: '100%',
                            width: `${Math.max(2, percent)}%`,
                            background: percent > 80 ? 'var(--accent-crimson)' : 'linear-gradient(90deg, var(--accent-cyan), var(--accent-emerald))',
                            borderRadius: '3px',
                          }}
                        />
                      </div>
                    </td>
                    <td style={{ padding: '14px 12px', fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-secondary)' }}>
                      {m.keySize}B / {m.valueSize}B
                    </td>
                    <td style={{ padding: '14px 12px', color: 'var(--text-muted)', fontSize: '12px' }}>
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
