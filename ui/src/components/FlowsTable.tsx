import React, { useState } from 'react';
import { Search, ArrowUpRight, ArrowDownLeft, CheckCircle2, XCircle, Info, ChevronRight } from 'lucide-react';
import type { FlowRecord } from '../types';

interface FlowsTableProps {
  flows: FlowRecord[];
}

export const FlowsTable: React.FC<FlowsTableProps> = ({ flows }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [verdictFilter, setVerdictFilter] = useState<'ALL' | 'PASS' | 'DROP'>('ALL');
  const [selectedFlow, setSelectedFlow] = useState<FlowRecord | null>(null);

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
    <div className="glass-panel" style={{ padding: '24px' }}>
      {/* Controls Bar */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '16px',
        marginBottom: '20px',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <h2 style={{ fontSize: '18px', fontWeight: 700, color: '#fff' }}>
            Live Kernel Flow Telemetry
          </h2>
          <span style={{
            fontSize: '11px',
            padding: '3px 9px',
            borderRadius: '999px',
            background: 'rgba(0, 240, 255, 0.15)',
            color: 'var(--accent-cyan)',
            fontWeight: 600,
          }}>
            RingBuffer: kw_flow_events
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          {/* Search box */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '8px',
            padding: '6px 12px',
          }}>
            <Search size={15} color="var(--text-muted)" />
            <input
              type="text"
              placeholder="Filter pod, IP, or port..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{
                background: 'transparent',
                border: 'none',
                outline: 'none',
                color: '#fff',
                fontSize: '13px',
                width: '180px',
              }}
            />
          </div>

          {/* Verdict Filter */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '8px',
            padding: '2px',
          }}>
            {(['ALL', 'PASS', 'DROP'] as const).map((v) => (
              <button
                key={v}
                onClick={() => setVerdictFilter(v)}
                style={{
                  padding: '5px 12px',
                  border: 'none',
                  borderRadius: '6px',
                  background: verdictFilter === v ? 'var(--bg-card-hover)' : 'transparent',
                  color: verdictFilter === v ? '#fff' : 'var(--text-muted)',
                  fontSize: '12px',
                  fontWeight: verdictFilter === v ? 600 : 500,
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                }}
              >
                {v}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Flows Table */}
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
          <thead>
            <tr style={{
              borderBottom: '1px solid var(--border-subtle)',
              color: 'var(--text-muted)',
              fontSize: '11px',
              textTransform: 'uppercase',
              letterSpacing: '0.5px',
            }}>
              <th style={{ padding: '12px 14px' }}>Time</th>
              <th style={{ padding: '12px 14px' }}>Direction</th>
              <th style={{ padding: '12px 14px' }}>Source Workload</th>
              <th style={{ padding: '12px 14px' }}>Destination Workload</th>
              <th style={{ padding: '12px 14px' }}>Protocol / Port</th>
              <th style={{ padding: '12px 14px' }}>Verdict</th>
              <th style={{ padding: '12px 14px' }}>Volume</th>
              <th style={{ padding: '12px 14px' }}></th>
            </tr>
          </thead>
          <tbody>
            {filteredFlows.length === 0 ? (
              <tr>
                <td colSpan={8} style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>
                  No matching network flows captured in buffer
                </td>
              </tr>
            ) : (
              filteredFlows.map((flow) => {
                const isPass = flow.verdict === 'PASS';
                return (
                  <tr
                    key={flow.id}
                    onClick={() => setSelectedFlow(flow)}
                    style={{
                      borderBottom: '1px solid var(--border-subtle)',
                      cursor: 'pointer',
                      transition: 'background 0.15s ease',
                      backgroundColor: selectedFlow?.id === flow.id ? 'rgba(0, 240, 255, 0.05)' : 'transparent',
                    }}
                    onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'var(--bg-card-hover)')}
                    onMouseLeave={(e) =>
                      (e.currentTarget.style.backgroundColor =
                        selectedFlow?.id === flow.id ? 'rgba(0, 240, 255, 0.05)' : 'transparent')
                    }
                  >
                    <td style={{ padding: '12px 14px', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                      {flow.timestamp}
                    </td>

                    <td style={{ padding: '12px 14px' }}>
                      <span style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '4px',
                        padding: '3px 8px',
                        borderRadius: '6px',
                        fontSize: '11px',
                        fontWeight: 600,
                        background: flow.direction === 'INGRESS' ? 'rgba(0, 240, 255, 0.1)' : 'rgba(168, 85, 247, 0.1)',
                        color: flow.direction === 'INGRESS' ? 'var(--accent-cyan)' : 'var(--accent-purple)',
                      }}>
                        {flow.direction === 'INGRESS' ? <ArrowDownLeft size={12} /> : <ArrowUpRight size={12} />}
                        {flow.direction}
                      </span>
                    </td>

                    <td style={{ padding: '12px 14px' }}>
                      <div style={{ fontWeight: 600, color: '#fff' }}>{flow.srcPod}</div>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                        {flow.srcIp} <span style={{ color: 'var(--accent-purple)' }}>[ID: {flow.srcIdentity}]</span>
                      </div>
                    </td>

                    <td style={{ padding: '12px 14px' }}>
                      <div style={{ fontWeight: 600, color: '#fff' }}>{flow.dstPod}</div>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                        {flow.dstIp} <span style={{ color: 'var(--accent-purple)' }}>[ID: {flow.dstIdentity}]</span>
                      </div>
                    </td>

                    <td style={{ padding: '12px 14px' }}>
                      <span style={{ fontWeight: 600, color: '#fff' }}>{flow.protocol}</span>
                      <span style={{ color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)', marginLeft: '6px' }}>
                        :{flow.dstPort}
                      </span>
                    </td>

                    <td style={{ padding: '12px 14px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        {isPass ? (
                          <CheckCircle2 size={15} color="var(--accent-green)" />
                        ) : (
                          <XCircle size={15} color="var(--accent-crimson)" />
                        )}
                        <span style={{
                          fontWeight: 700,
                          fontSize: '12px',
                          color: isPass ? 'var(--accent-green)' : 'var(--accent-crimson)',
                        }}>
                          {flow.verdict}
                        </span>
                      </div>
                      {flow.dropReason && (
                        <div style={{ fontSize: '11px', color: 'var(--accent-crimson)', marginTop: '2px' }}>
                          {flow.dropReason}
                        </div>
                      )}
                    </td>

                    <td style={{ padding: '12px 14px', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                      {(flow.bytes / 1024).toFixed(1)} KB
                      <span style={{ fontSize: '11px', color: 'var(--text-muted)', marginLeft: '4px' }}>
                        ({flow.packets} pkts)
                      </span>
                    </td>

                    <td style={{ padding: '12px 14px', textAlign: 'right' }}>
                      <ChevronRight size={16} color="var(--text-muted)" />
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Flow Inspector Drawer Modal */}
      {selectedFlow && (
        <div style={{
          marginTop: '20px',
          padding: '18px 24px',
          borderRadius: '10px',
          background: 'var(--bg-secondary)',
          border: '1px solid var(--accent-cyan)',
          boxShadow: '0 0 20px rgba(0, 240, 255, 0.1)',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Info size={18} color="var(--accent-cyan)" />
              <h3 style={{ fontSize: '15px', fontWeight: 700, color: '#fff' }}>
                Kernel Flow Event Inspector: {selectedFlow.id}
              </h3>
            </div>
            <button
              onClick={() => setSelectedFlow(null)}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--text-muted)',
                cursor: 'pointer',
                fontSize: '13px',
              }}
            >
              ✕ Close
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '14px', fontSize: '12px' }}>
            <div>
              <span style={{ color: 'var(--text-muted)' }}>Source:</span>
              <div style={{ fontFamily: 'var(--font-mono)', color: '#fff' }}>{selectedFlow.srcIp}:{selectedFlow.srcPort}</div>
              <div style={{ color: 'var(--accent-purple)' }}>Pod: {selectedFlow.srcPod} (ID: {selectedFlow.srcIdentity})</div>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)' }}>Destination:</span>
              <div style={{ fontFamily: 'var(--font-mono)', color: '#fff' }}>{selectedFlow.dstIp}:{selectedFlow.dstPort}</div>
              <div style={{ color: 'var(--accent-purple)' }}>Pod: {selectedFlow.dstPod} (ID: {selectedFlow.dstIdentity})</div>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)' }}>eBPF Hook Layer:</span>
              <div style={{ color: '#fff' }}>TC / TCX (kwall_tc_{selectedFlow.direction.toLowerCase()})</div>
              <div style={{ color: 'var(--accent-cyan)' }}>Netkit Zero-Copy Path</div>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)' }}>Verdict Enforcement:</span>
              <div style={{ fontWeight: 700, color: selectedFlow.verdict === 'PASS' ? 'var(--accent-green)' : 'var(--accent-crimson)' }}>
                {selectedFlow.verdict}
              </div>
              <div style={{ color: 'var(--text-secondary)' }}>{selectedFlow.dropReason || 'Matched Allow Rule'}</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
