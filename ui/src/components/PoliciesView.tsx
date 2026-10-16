import React, { useState, useEffect } from 'react';
import { Shield } from 'lucide-react';
import type { IKwallPolicyRule, IKwallPolicyCompilationResult } from '../types';
import type { IKwallApiClient } from '../services';

export interface IPoliciesViewProps {
  policies: IKwallPolicyRule[];
  apiClient: IKwallApiClient;
}

export const PoliciesView: React.FC<IPoliciesViewProps> = ({ policies, apiClient }) => {
  const [selectedPolicy, setSelectedPolicy] = useState<IKwallPolicyRule | null>(policies[0] || null);
  const [activeTab, setActiveTab] = useState<'rules' | 'compiler_ir' | 'raw_crd'>('rules');
  const [compilationResult, setCompilationResult] = useState<IKwallPolicyCompilationResult | null>(null);
  const [isCompiling, setIsCompiling] = useState<boolean>(false);

  useEffect(() => {
    if (selectedPolicy) {
      let isMounted = true;
      setIsCompiling(true);
      apiClient.compilePolicy(selectedPolicy)
        .then((res) => {
          if (isMounted) setCompilationResult(res);
        })
        .finally(() => {
          if (isMounted) setIsCompiling(false);
        });

      return () => {
        isMounted = false;
      };
    }
  }, [selectedPolicy, apiClient]);

  return (
    <div className="flex flex-col gap-6">
      {/* Top Header Summary */}
      <div className="glass-panel p-6 shadow-xl">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-xl font-extrabold text-white flex items-center gap-2.5">
              <Shield className="w-6 h-6 text-purple-400" />
              KWALL Distributed Policy Engine
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Compiles Kubernetes NetworkPolicies & KWALL SecurityPolicies into deterministic identity-based eBPF hash tables.
            </p>
          </div>
          <div className="flex gap-3">
            <div className="px-4 py-2 rounded-lg bg-slate-900 border border-white/10 text-xs">
              <span className="text-slate-400">Active Policies: </span>
              <strong className="text-white font-mono">{policies.length}</strong>
            </div>
            <div className="px-4 py-2 rounded-lg bg-slate-900 border border-white/10 text-xs">
              <span className="text-slate-400">Compilation Latency: </span>
              <strong className="text-emerald-400 font-mono">
                {compilationResult ? `${compilationResult.compilationLatencyMs} ms` : 'calculating...'}
              </strong>
            </div>
          </div>
        </div>
      </div>

      {/* Main 2-column layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        {/* Left Column: Policy List */}
        <div className="glass-panel p-5 flex flex-col gap-3 shadow-lg">
          <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider">
            Enforced Policies ({policies.length})
          </h3>

          <div className="flex flex-col gap-2">
            {policies.map((pol) => {
              const isSelected = selectedPolicy?.id === pol.id;
              return (
                <div
                  key={pol.id}
                  onClick={() => setSelectedPolicy(pol)}
                  className={`p-3.5 rounded-xl cursor-pointer transition-all border ${
                    isSelected
                      ? 'bg-purple-500/15 border-purple-400 shadow-md shadow-purple-500/10'
                      : 'bg-slate-900/60 border-white/10 hover:border-white/20'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-bold text-white text-xs truncate max-w-[200px]" title={pol.name}>
                      {pol.name}
                    </span>
                    <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                      {pol.state}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400 flex justify-between font-mono">
                    <span>ns: <strong className="text-slate-300">{pol.namespace}</strong></span>
                    <span>app: <strong className="text-cyan-400">{pol.targetApp}</strong></span>
                    <span>{pol.activeNodes} nodes</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Selected Policy Deep Dive */}
        {selectedPolicy && (
          <div className="lg:col-span-2 glass-panel p-6 flex flex-col gap-5 shadow-xl">
            <div className="flex flex-wrap items-center justify-between border-b border-white/10 pb-4 gap-3">
              <div>
                <div className="flex items-center gap-2.5">
                  <h3 className="text-lg font-bold text-white">{selectedPolicy.name}</h3>
                  <span className="text-xs font-mono bg-purple-500/10 text-purple-400 border border-purple-500/30 px-2 py-0.5 rounded">
                    app={selectedPolicy.targetApp}
                  </span>
                </div>
                <div className="text-xs text-slate-400 mt-1">
                  Namespace: <span className="text-white font-medium">{selectedPolicy.namespace}</span> • Synchronized across {selectedPolicy.activeNodes} netkit worker nodes
                </div>
              </div>

              {/* Sub-tabs */}
              <div className="flex gap-1.5 bg-slate-900 border border-white/10 p-0.5 rounded-lg text-xs">
                {(['rules', 'compiler_ir', 'raw_crd'] as const).map((t) => (
                  <button
                    key={t}
                    onClick={() => setActiveTab(t)}
                    className={`px-3 py-1 rounded font-semibold transition-all ${
                      activeTab === t ? 'bg-purple-500 text-white shadow-sm' : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    {t === 'rules' ? 'Rules Spec' : t === 'compiler_ir' ? 'eBPF IR Output' : 'CRD YAML'}
                  </button>
                ))}
              </div>
            </div>

            {/* Tab: Rules View */}
            {activeTab === 'rules' && (
              <div className="flex flex-col gap-5">
                <div>
                  <h4 className="text-xs font-bold text-cyan-400 uppercase tracking-wider mb-2">
                    Ingress Rules ({selectedPolicy.ingressRules.length})
                  </h4>
                  {selectedPolicy.ingressRules.length === 0 ? (
                    <div className="p-3 bg-slate-900/60 rounded-lg text-xs text-slate-500">
                      No ingress permitted (Default Deny).
                    </div>
                  ) : (
                    selectedPolicy.ingressRules.map((r, idx) => (
                      <div key={idx} className="p-3.5 bg-slate-900/80 rounded-xl border border-white/10 mb-2">
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-xs text-slate-300">
                            Allowed Sources: <strong className="text-white font-mono">{r.from.join(', ')}</strong>
                          </span>
                          <span className="text-[10px] font-bold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/30">
                            {r.action}
                          </span>
                        </div>
                        <div className="flex gap-2">
                          {r.ports.map((p, pIdx) => (
                            <span key={pIdx} className="text-[11px] font-mono px-2 py-0.5 bg-slate-950 rounded text-cyan-400 border border-white/10">
                              Port {p.port}/{p.protocol}
                            </span>
                          ))}
                        </div>
                      </div>
                    ))
                  )}
                </div>

                <div>
                  <h4 className="text-xs font-bold text-cyan-400 uppercase tracking-wider mb-2">
                    Egress Rules ({selectedPolicy.egressRules.length})
                  </h4>
                  {selectedPolicy.egressRules.length === 0 ? (
                    <div className="p-3 bg-slate-900/60 rounded-lg text-xs text-slate-500">
                      No egress permitted (Default Deny).
                    </div>
                  ) : (
                    selectedPolicy.egressRules.map((r, idx) => (
                      <div key={idx} className="p-3.5 bg-slate-900/80 rounded-xl border border-white/10 mb-2">
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-xs text-slate-300">
                            Allowed Destinations: <strong className="text-white font-mono">{r.to.join(', ')}</strong>
                          </span>
                          <span className="text-[10px] font-bold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/30">
                            {r.action}
                          </span>
                        </div>
                        <div className="flex gap-2">
                          {r.ports.map((p, pIdx) => (
                            <span key={pIdx} className="text-[11px] font-mono px-2 py-0.5 bg-slate-950 rounded text-cyan-400 border border-white/10">
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
                <div className="text-xs text-slate-400 mb-3">
                  Dynamically compiled Aya BPF hash table entries from <code className="text-cyan-400 font-mono">kwall-policy::PolicyCompiler</code>:
                </div>
                {isCompiling ? (
                  <div className="py-8 text-center text-xs text-slate-400">Compiling policy rules into eBPF IR...</div>
                ) : (
                  <div className="flex flex-col gap-2 font-mono text-xs">
                    {compilationResult?.bpfRules.map((rule, idx) => (
                      <div
                        key={idx}
                        className="p-3 rounded-lg bg-slate-950 border border-white/10 flex flex-col gap-1.5"
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-purple-400 font-bold">{rule.mapName}</span>
                          <span className={`text-[10px] ${rule.verificationStatus.includes('DROP') ? 'text-rose-400' : 'text-emerald-400'}`}>
                            {rule.verificationStatus}
                          </span>
                        </div>
                        <div className="text-slate-300">
                          <strong className="text-slate-500">KEY: </strong>
                          {rule.keyRepresentation}
                        </div>
                        <div className="text-cyan-400">
                          <strong className="text-slate-500">VAL: </strong>
                          {rule.valueRepresentation}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Tab: Raw CRD */}
            {activeTab === 'raw_crd' && (
              <pre className="p-4 rounded-xl bg-slate-950 border border-white/10 font-mono text-xs text-slate-300 overflow-x-auto leading-relaxed">
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
