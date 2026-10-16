import React, { useState } from 'react';
import { Shield } from 'lucide-react';
import type { PolicyRule } from '../types';

interface PoliciesViewProps {
  policies: PolicyRule[];
}

export const PoliciesView: React.FC<PoliciesViewProps> = ({ policies }) => {
  const [selectedPolicy, setSelectedPolicy] = useState<PolicyRule>(policies[0]);
  const [activeTab, setActiveTab] = useState<'rules' | 'compiler_ir' | 'raw_crd'>('rules');

  // Simulated compiled eBPF IR
  const compiledBpfRules = [
    {
      map: 'kw_policies',
      key: '{ src_id: 1042, dst_id: 1045, port: 8080, proto: 6 }',
      val: '{ action: PASS, flags: 0x01, counter_idx: 12 }',
      state: 'VERIFIED_ACTIVE',
    },
    {
      map: 'kw_policies',
      key: '{ src_id: 1045, dst_id: 1099, port: 443, proto: 6 }',
      val: '{ action: PASS, flags: 0x01, counter_idx: 14 }',
      state: 'VERIFIED_ACTIVE',
    },
    {
      map: 'kw_policies',
      key: '{ src_id: 2, dst_id: 1042, port: 22, proto: 6 }',
      val: '{ action: DROP, flags: 0x02, counter_idx: 99 }',
      state: 'VERIFIED_ACTIVE',
    },
    {
      map: 'kw_policies',
      key: '{ src_id: *, dst_id: *, port: *, proto: * }',
      val: '{ action: DROP, flags: 0x00, counter_idx: 0 }',
      state: 'DEFAULT_DENY_FALLTHROUGH',
    },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Header Summary */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <h2 style={{ fontSize: '20px', fontWeight: 800, color: '#fff', display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Shield size={22} color="var(--accent-purple)" />
              KWALL Distributed Policy Engine
            </h2>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '4px' }}>
              Compiles Kubernetes NetworkPolicies & KWALL SecurityPolicies into deterministic identity-based eBPF hash tables.
            </p>
          </div>
          <div style={{ display: 'flex', gap: '12px' }}>
            <div style={{
              padding: '8px 16px',
              borderRadius: '8px',
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border-subtle)',
              fontSize: '12px',
            }}>
              <span style={{ color: 'var(--text-muted)' }}>Active Policies: </span>
              <strong style={{ color: '#fff' }}>{policies.length}</strong>
            </div>
            <div style={{
              padding: '8px 16px',
              borderRadius: '8px',
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border-subtle)',
              fontSize: '12px',
            }}>
              <span style={{ color: 'var(--text-muted)' }}>Compiler Latency: </span>
              <strong style={{ color: 'var(--accent-emerald)' }}>0.42 ms</strong>
            </div>
          </div>
        </div>
      </div>

      {/* Main 2-column layout */}
      <div style={{ display: 'grid', gridTemplateColumns: '380px 1fr', gap: '24px', alignItems: 'start' }}>
        {/* Left Column: Policy List */}
        <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <h3 style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
            Enforced Policies ({policies.length})
          </h3>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {policies.map((pol) => {
              const isSelected = selectedPolicy?.id === pol.id;
              return (
                <div
                  key={pol.id}
                  onClick={() => setSelectedPolicy(pol)}
                  style={{
                    padding: '14px 16px',
                    borderRadius: '8px',
                    background: isSelected ? 'rgba(168, 85, 247, 0.12)' : 'var(--bg-secondary)',
                    border: isSelected ? '1px solid var(--accent-purple)' : '1px solid var(--border-subtle)',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                    <span style={{ fontWeight: 700, color: '#fff', fontSize: '13px' }}>{pol.name}</span>
                    <span style={{
                      fontSize: '10px',
                      fontWeight: 700,
                      padding: '2px 6px',
                      borderRadius: '4px',
                      background: 'rgba(16, 185, 129, 0.15)',
                      color: 'var(--accent-emerald)',
                      border: '1px solid var(--accent-emerald)',
                    }}>
                      {pol.state}
                    </span>
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'flex', justifyContent: 'space-between' }}>
                    <span>ns: <strong>{pol.namespace}</strong></span>
                    <span>app: <strong>{pol.targetApp}</strong></span>
                    <span>{pol.activeNodes} nodes</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Selected Policy Deep Dive */}
        {selectedPolicy && (
          <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '16px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <h3 style={{ fontSize: '18px', fontWeight: 800, color: '#fff' }}>{selectedPolicy.name}</h3>
                  <span style={{
                    fontSize: '11px',
                    fontFamily: 'var(--font-mono)',
                    background: 'var(--bg-secondary)',
                    padding: '2px 8px',
                    borderRadius: '4px',
                    color: 'var(--accent-purple)',
                  }}>
                    app={selectedPolicy.targetApp}
                  </span>
                </div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                  Namespace: <span style={{ color: '#fff' }}>{selectedPolicy.namespace}</span> • Sync Status: Synchronized across {selectedPolicy.activeNodes} netkit worker nodes
                </div>
              </div>

              {/* Sub-tabs */}
              <div style={{ display: 'flex', gap: '6px' }}>
                <button
                  onClick={() => setActiveTab('rules')}
                  style={{
                    padding: '6px 12px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontWeight: 600,
                    border: 'none',
                    background: activeTab === 'rules' ? 'var(--accent-purple)' : 'var(--bg-secondary)',
                    color: activeTab === 'rules' ? '#fff' : 'var(--text-secondary)',
                    cursor: 'pointer',
                  }}
                >
                  Rules Spec
                </button>
                <button
                  onClick={() => setActiveTab('compiler_ir')}
                  style={{
                    padding: '6px 12px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontWeight: 600,
                    border: 'none',
                    background: activeTab === 'compiler_ir' ? 'var(--accent-purple)' : 'var(--bg-secondary)',
                    color: activeTab === 'compiler_ir' ? '#fff' : 'var(--text-secondary)',
                    cursor: 'pointer',
                  }}
                >
                  eBPF IR Output
                </button>
                <button
                  onClick={() => setActiveTab('raw_crd')}
                  style={{
                    padding: '6px 12px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontWeight: 600,
                    border: 'none',
                    background: activeTab === 'raw_crd' ? 'var(--accent-purple)' : 'var(--bg-secondary)',
                    color: activeTab === 'raw_crd' ? '#fff' : 'var(--text-secondary)',
                    cursor: 'pointer',
                  }}
                >
                  CRD YAML
                </button>
              </div>
            </div>

            {/* Tab: Rules View */}
            {activeTab === 'rules' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div>
                  <h4 style={{ fontSize: '13px', fontWeight: 700, color: 'var(--accent-cyan)', marginBottom: '8px', textTransform: 'uppercase' }}>
                    Ingress Rules ({selectedPolicy.ingressRules.length})
                  </h4>
                  {selectedPolicy.ingressRules.length === 0 ? (
                    <div style={{ padding: '12px', background: 'var(--bg-secondary)', borderRadius: '6px', fontSize: '12px', color: 'var(--text-muted)' }}>
                      No ingress permitted (Default Deny).
                    </div>
                  ) : (
                    selectedPolicy.ingressRules.map((r, idx) => (
                      <div key={idx} style={{ padding: '14px', background: 'var(--bg-secondary)', borderRadius: '8px', border: '1px solid var(--border-subtle)', marginBottom: '8px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                          <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                            Allowed Sources: <strong style={{ color: '#fff' }}>{r.from.join(', ')}</strong>
                          </span>
                          <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--accent-emerald)', background: 'rgba(16, 185, 129, 0.1)', padding: '2px 8px', borderRadius: '4px' }}>
                            {r.action}
                          </span>
                        </div>
                        <div style={{ display: 'flex', gap: '8px' }}>
                          {r.ports.map((p, pIdx) => (
                            <span key={pIdx} style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', padding: '2px 8px', background: 'var(--bg-tertiary)', borderRadius: '4px', color: 'var(--accent-cyan)' }}>
                              Port {p.port}/{p.protocol}
                            </span>
                          ))}
                        </div>
                      </div>
                    ))
                  )}
                </div>

                <div>
                  <h4 style={{ fontSize: '13px', fontWeight: 700, color: 'var(--accent-cyan)', marginBottom: '8px', textTransform: 'uppercase' }}>
                    Egress Rules ({selectedPolicy.egressRules.length})
                  </h4>
                  {selectedPolicy.egressRules.length === 0 ? (
                    <div style={{ padding: '12px', background: 'var(--bg-secondary)', borderRadius: '6px', fontSize: '12px', color: 'var(--text-muted)' }}>
                      No egress permitted (Default Deny).
                    </div>
                  ) : (
                    selectedPolicy.egressRules.map((r, idx) => (
                      <div key={idx} style={{ padding: '14px', background: 'var(--bg-secondary)', borderRadius: '8px', border: '1px solid var(--border-subtle)', marginBottom: '8px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                          <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                            Allowed Destinations: <strong style={{ color: '#fff' }}>{r.to.join(', ')}</strong>
                          </span>
                          <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--accent-emerald)', background: 'rgba(16, 185, 129, 0.1)', padding: '2px 8px', borderRadius: '4px' }}>
                            {r.action}
                          </span>
                        </div>
                        <div style={{ display: 'flex', gap: '8px' }}>
                          {r.ports.map((p, pIdx) => (
                            <span key={pIdx} style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', padding: '2px 8px', background: 'var(--bg-tertiary)', borderRadius: '4px', color: 'var(--accent-cyan)' }}>
                              Port {p.port}/{p.protocol}
                            </span>
                          ))}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}

            {/* Tab: Compiler IR */}
            {activeTab === 'compiler_ir' && (
              <div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '12px' }}>
                  Aya BPF map entries generated by <code style={{ color: 'var(--accent-cyan)' }}>kwall-policy::PolicyOptimizer</code>:
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {compiledBpfRules.map((rule, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: '12px 14px',
                        borderRadius: '6px',
                        background: 'var(--bg-primary)',
                        border: '1px solid var(--border-subtle)',
                        fontFamily: 'var(--font-mono)',
                        fontSize: '12px',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '6px',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <span style={{ color: 'var(--accent-purple)' }}>{rule.map}</span>
                        <span style={{ fontSize: '10px', color: rule.state.includes('DROP') ? 'var(--accent-crimson)' : 'var(--accent-emerald)' }}>
                          {rule.state}
                        </span>
                      </div>
                      <div style={{ color: 'var(--text-secondary)' }}>
                        <strong style={{ color: 'var(--text-muted)' }}>KEY: </strong>
                        {rule.key}
                      </div>
                      <div style={{ color: 'var(--accent-cyan)' }}>
                        <strong style={{ color: 'var(--text-muted)' }}>VAL: </strong>
                        {rule.val}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Tab: Raw CRD */}
            {activeTab === 'raw_crd' && (
              <pre style={{
                margin: 0,
                padding: '16px',
                borderRadius: '8px',
                background: 'var(--bg-primary)',
                border: '1px solid var(--border-subtle)',
                fontFamily: 'var(--font-mono)',
                fontSize: '12px',
                color: 'var(--text-secondary)',
                lineHeight: 1.6,
                overflowX: 'auto',
              }}>
{`apiVersion: kwall.io/v1alpha1
kind: KWALLNetworkPolicy
metadata:
  name: ${selectedPolicy.name}
  namespace: ${selectedPolicy.namespace}
spec:
  selector:
    matchLabels:
      app: ${selectedPolicy.targetApp}
  ingress:
${selectedPolicy.ingressRules.map(r => `    - from:
${r.from.map(f => `        - podSelector:\n            matchLabels:\n              app: ${f}`).join('\n')}
      ports:
${r.ports.map(p => `        - port: ${p.port}\n          protocol: ${p.protocol}`).join('\n')}`).join('\n')}
  egress:
${selectedPolicy.egressRules.map(r => `    - to:
${r.to.map(t => `        - podSelector:\n            matchLabels:\n              app: ${t}`).join('\n')}
      ports:
${r.ports.map(p => `        - port: ${p.port}\n          protocol: ${p.protocol}`).join('\n')}`).join('\n')}
  policyTypes:
    - Ingress
    - Egress`}
              </pre>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
