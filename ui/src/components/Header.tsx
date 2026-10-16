import React from 'react';
import { Shield, Cpu, Network, Play, Pause } from 'lucide-react';
import type { NodeStatus } from '../types';

interface HeaderProps {
  status: NodeStatus;
  isStreaming: boolean;
  onToggleStreaming: () => void;
  activeTab: string;
  onSelectTab: (tab: string) => void;
}

export const Header: React.FC<HeaderProps> = ({
  status,
  isStreaming,
  onToggleStreaming,
  activeTab,
  onSelectTab,
}) => {
  return (
    <header style={{
      borderBottom: '1px solid var(--border-subtle)',
      background: 'rgba(7, 9, 14, 0.85)',
      backdropFilter: 'blur(16px)',
      position: 'sticky',
      top: 0,
      zIndex: 50,
      padding: '0 24px',
    }}>
      {/* Top Banner */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        height: '68px',
        borderBottom: '1px solid var(--border-subtle)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '42px',
            height: '42px',
            borderRadius: '10px',
            background: 'linear-gradient(135deg, rgba(0, 240, 255, 0.2), rgba(16, 185, 129, 0.2))',
            border: '1px solid var(--accent-cyan)',
            boxShadow: '0 0 15px rgba(0, 240, 255, 0.25)',
          }}>
            <Shield size={24} color="#00f0ff" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <h1 style={{ fontSize: '20px', fontWeight: 800, letterSpacing: '-0.5px', color: '#fff' }}>
                KWALL
              </h1>
              <span style={{
                fontSize: '11px',
                fontWeight: 600,
                padding: '2px 8px',
                borderRadius: '999px',
                background: 'rgba(0, 240, 255, 0.1)',
                color: 'var(--accent-cyan)',
                border: '1px solid rgba(0, 240, 255, 0.3)',
                textTransform: 'uppercase',
                letterSpacing: '0.5px'
              }}>
                eBPF + Netkit
              </span>
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Kubernetes Dataplane & Runtime Security Platform
            </p>
          </div>
        </div>

        {/* Kernel & Node status badges */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '18px' }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '6px 14px',
            borderRadius: '8px',
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border-subtle)',
            fontSize: '12px',
          }}>
            <Cpu size={15} color="var(--accent-cyan)" />
            <span style={{ color: 'var(--text-secondary)' }}>Node:</span>
            <span style={{ fontWeight: 600, color: '#fff', fontFamily: 'var(--font-mono)' }}>{status.nodeName}</span>
            <span className="pulse-dot green" title="Kernel compatible and eBPF active" />
          </div>

          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '6px 14px',
            borderRadius: '8px',
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border-subtle)',
            fontSize: '12px',
          }}>
            <Network size={15} color="var(--accent-green)" />
            <span style={{ color: 'var(--text-secondary)' }}>Netkit:</span>
            <span style={{ fontWeight: 600, color: 'var(--accent-green)' }}>
              {status.netkitActive ? 'ACTIVE' : 'STANDBY'}
            </span>
          </div>

          {/* Stream Controls */}
          <button
            onClick={onToggleStreaming}
            id="toggle-stream-btn"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              padding: '8px 16px',
              borderRadius: '8px',
              border: isStreaming ? '1px solid var(--accent-cyan)' : '1px solid var(--border-medium)',
              background: isStreaming ? 'rgba(0, 240, 255, 0.12)' : 'var(--bg-secondary)',
              color: isStreaming ? 'var(--accent-cyan)' : 'var(--text-secondary)',
              cursor: 'pointer',
              fontSize: '13px',
              fontWeight: 600,
              transition: 'all 0.2s',
            }}
          >
            {isStreaming ? <Pause size={15} /> : <Play size={15} />}
            {isStreaming ? 'Live Streaming' : 'Paused'}
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <nav style={{ display: 'flex', gap: '8px', paddingTop: '10px', paddingBottom: '10px' }}>
        {[
          { id: 'overview', label: 'Overview' },
          { id: 'flows', label: 'eBPF Flow Stream' },
          { id: 'threats', label: 'Threat Center & DDoS' },
          { id: 'policies', label: 'Policy Engine' },
          { id: 'dataplane', label: 'Kernel Maps & Netkit' },
        ].map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => onSelectTab(tab.id)}
              id={`tab-${tab.id}`}
              style={{
                padding: '8px 18px',
                borderRadius: '8px',
                border: 'none',
                background: isActive ? 'rgba(0, 240, 255, 0.12)' : 'transparent',
                color: isActive ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                fontWeight: isActive ? 600 : 500,
                fontSize: '13px',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
                outline: 'none',
                boxShadow: isActive ? '0 0 12px rgba(0, 240, 255, 0.15)' : 'none',
              }}
            >
              {tab.label}
            </button>
          );
        })}
      </nav>
    </header>
  );
};
