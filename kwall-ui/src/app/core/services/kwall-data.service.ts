import { Injectable, signal, computed, effect } from '@angular/core';

export interface ClusterMetrics {
  packetsTotal: number;
  bytesTotal: number;
  dropsTotal: number;
  activeConntrack: number;
  threatsBlocked: number;
  latencyP95Us: number;
  latencyP99Us: number;
  packetsPerSec: number;
  dropsPerSec: number;
}

export interface FlowRecord {
  id: string;
  timestamp: string;
  srcIdentity: number;
  srcWorkload: string;
  srcIp: string;
  srcPort: number;
  dstIdentity: number;
  dstWorkload: string;
  dstIp: string;
  dstPort: number;
  protocol: 'TCP' | 'UDP' | 'ICMP';
  direction: 'Ingress' | 'Egress';
  action: 'PASS' | 'DROP';
  dropReason?: string;
  packets: number;
  bytes: number;
  policyId: number;
}

export interface SecurityAlert {
  id: string;
  timestamp: string;
  eventType: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  source: string;
  target: string;
  details: string;
}

export interface WorkloadEndpoint {
  identityId: number;
  namespace: string;
  podName: string;
  podUid: string;
  ip: string;
  node: string;
  status: string;
  ifindex: number;
}

export interface SecurityPolicyItem {
  name: string;
  namespace: string;
  kind: 'KWALLNetworkPolicy' | 'KWALLSecurityPolicy' | 'KWALLRuntimePolicy' | 'KWALLDDoSPolicy' | 'KWALLFlowPolicy';
  selector: string;
  rulesCount: number;
  action: string;
  status: string;
}

export interface NodeHealth {
  name: string;
  kernelVersion: string;
  ebpfStatus: 'Loaded' | 'Degraded' | 'Offline';
  netkitStatus: 'Active' | 'Inactive';
  cpuUsagePct: number;
  memoryUsageMb: number;
  interfaces: string[];
}

@Injectable({
  providedIn: 'root'
})
export class KwallDataService {
  // Reactive Signals State
  readonly metrics = signal<ClusterMetrics>({
    packetsTotal: 14829140,
    bytesTotal: 12489204890,
    dropsTotal: 14209,
    activeConntrack: 8421,
    threatsBlocked: 342,
    latencyP95Us: 4.2,
    latencyP99Us: 8.7,
    packetsPerSec: 14200,
    dropsPerSec: 24,
  });

  readonly flows = signal<FlowRecord[]>([
    {
      id: 'fl-1',
      timestamp: '11:52:14.412',
      srcIdentity: 1042,
      srcWorkload: 'frontend-67d98-x2z',
      srcIp: '10.244.1.42',
      srcPort: 48922,
      dstIdentity: 1043,
      dstWorkload: 'order-api-89fb-k91',
      dstIp: '10.244.2.18',
      dstPort: 8080,
      protocol: 'TCP',
      direction: 'Ingress',
      action: 'PASS',
      packets: 142,
      bytes: 84920,
      policyId: 101,
    },
    {
      id: 'fl-2',
      timestamp: '11:52:14.398',
      srcIdentity: 2, // World
      srcWorkload: 'external-client',
      srcIp: '198.51.100.4',
      srcPort: 54112,
      dstIdentity: 1042,
      dstWorkload: 'frontend-67d98-x2z',
      dstIp: '10.244.1.42',
      dstPort: 443,
      protocol: 'TCP',
      direction: 'Ingress',
      action: 'PASS',
      packets: 68,
      bytes: 34100,
      policyId: 100,
    },
    {
      id: 'fl-3',
      timestamp: '11:52:14.102',
      srcIdentity: 1099,
      srcWorkload: 'unauthorized-probe',
      srcIp: '10.244.3.88',
      srcPort: 39102,
      dstIdentity: 1055,
      dstWorkload: 'vault-auth-db-0',
      dstIp: '10.244.2.99',
      dstPort: 5432,
      protocol: 'TCP',
      direction: 'Egress',
      action: 'DROP',
      dropReason: 'PolicyDeny',
      packets: 1,
      bytes: 60,
      policyId: 0,
    },
    {
      id: 'fl-4',
      timestamp: '11:52:13.920',
      srcIdentity: 2,
      srcWorkload: 'external-botnet',
      srcIp: '203.0.113.19',
      srcPort: 44901,
      dstIdentity: 1, // Host
      dstWorkload: 'k8s-node-01 (Host SSH)',
      dstIp: '192.168.1.10',
      dstPort: 22,
      protocol: 'TCP',
      direction: 'Ingress',
      action: 'DROP',
      dropReason: 'PortScanDetected',
      packets: 12,
      bytes: 720,
      policyId: 0,
    },
    {
      id: 'fl-5',
      timestamp: '11:52:13.805',
      srcIdentity: 1043,
      srcWorkload: 'order-api-89fb-k91',
      srcIp: '10.244.2.18',
      srcPort: 38910,
      dstIdentity: 1050,
      dstWorkload: 'payment-gateway-12a',
      dstIp: '10.244.1.95',
      dstPort: 8443,
      protocol: 'TCP',
      direction: 'Egress',
      action: 'PASS',
      packets: 410,
      bytes: 320190,
      policyId: 102,
    }
  ]);

  readonly alerts = signal<SecurityAlert[]>([
    {
      id: 'alt-1',
      timestamp: '11:52:13',
      eventType: 'VolumetricDDoS (XDP)',
      severity: 'Critical',
      source: '203.0.113.19',
      target: 'k8s-node-01 (eth0)',
      details: 'Early XDP drop triggered: Token-bucket exceeded (SYN Flood 4,200 pps)',
    },
    {
      id: 'alt-2',
      timestamp: '11:51:48',
      eventType: 'DNS Tunneling',
      severity: 'High',
      source: 'identity: 1099 (unauthorized-probe)',
      target: 'dns.internal (port 53)',
      details: 'High entropy subdomain resolution: aGVsbG8td29ybGQtdGhpcy1pcy1leGZpbHQ.evil.com',
    },
    {
      id: 'alt-3',
      timestamp: '11:49:10',
      eventType: 'UntrustedBinary Execution',
      severity: 'Critical',
      source: 'pod: payment-gateway-12a (pid: 4892)',
      target: '/tmp/xmrig-miner',
      details: 'Runtime security alert: Execution detected from suspicious ephemeral path (/tmp)',
    },
    {
      id: 'alt-4',
      timestamp: '11:42:05',
      eventType: 'PortScan',
      severity: 'Medium',
      source: 'identity: 1042 (frontend-67d98-x2z)',
      target: '10.244.2.0/24',
      details: 'Probed 14 distinct TCP ports within 1 second window',
    }
  ]);

  readonly workloads = signal<WorkloadEndpoint[]>([
    {
      identityId: 1042,
      namespace: 'production',
      podName: 'frontend-67d98-x2z',
      podUid: '8a2b3c4d-11e2-4f99-90aa-0123456789ab',
      ip: '10.244.1.42',
      node: 'k8s-node-01',
      status: 'Running',
      ifindex: 4,
    },
    {
      identityId: 1043,
      namespace: 'production',
      podName: 'order-api-89fb-k91',
      podUid: '9f8e7d6c-22a1-4e88-81bb-9876543210fe',
      ip: '10.244.2.18',
      node: 'k8s-node-02',
      status: 'Running',
      ifindex: 5,
    },
    {
      identityId: 1050,
      namespace: 'payments',
      podName: 'payment-gateway-12a',
      podUid: '1a2b3c4d-33c4-4d77-92cc-4567890123ef',
      ip: '10.244.1.95',
      node: 'k8s-node-01',
      status: 'Running',
      ifindex: 6,
    },
    {
      identityId: 1055,
      namespace: 'database',
      podName: 'vault-auth-db-0',
      podUid: '7c8d9e0f-44d5-4c66-83dd-2345678901fa',
      ip: '10.244.2.99',
      node: 'k8s-node-02',
      status: 'Running',
      ifindex: 7,
    }
  ]);

  readonly policies = signal<SecurityPolicyItem[]>([
    {
      name: 'isolate-database-tier',
      namespace: 'database',
      kind: 'KWALLNetworkPolicy',
      selector: 'app: vault-auth-db',
      rulesCount: 2,
      action: 'Allow from production/order-api, Deny all other',
      status: 'Active',
    },
    {
      name: 'strict-lsm-runtime-guard',
      namespace: 'payments',
      kind: 'KWALLRuntimePolicy',
      selector: 'tier: secure-payment',
      rulesCount: 4,
      action: 'Block execution from /tmp, Enforce binary hashes',
      status: 'Enforced',
    },
    {
      name: 'global-cluster-ddos-mitigation',
      namespace: 'kube-system',
      kind: 'KWALLDDoSPolicy',
      selector: 'all-cluster-ingress',
      rulesCount: 3,
      action: 'XDP early drop: SYN > 1,000 pps, UDP > 5,000 pps',
      status: 'Enforced',
    },
    {
      name: 'flow-telemetry-sampling',
      namespace: 'production',
      kind: 'KWALLFlowPolicy',
      selector: 'all-pods',
      rulesCount: 1,
      action: 'Sample rate: 1:1, Export to Loki & Prometheus',
      status: 'Active',
    }
  ]);

  readonly nodes = signal<NodeHealth[]>([
    {
      name: 'k8s-node-01',
      kernelVersion: 'Linux 6.8.0-kwall (BTF + CO-RE)',
      ebpfStatus: 'Loaded',
      netkitStatus: 'Active',
      cpuUsagePct: 14.2,
      memoryUsageMb: 842,
      interfaces: ['eth0 (XDP)', 'kw_pri0 (TC Ingress/Egress)', 'kw_pri1'],
    },
    {
      name: 'k8s-node-02',
      kernelVersion: 'Linux 6.8.0-kwall (BTF + CO-RE)',
      ebpfStatus: 'Loaded',
      netkitStatus: 'Active',
      cpuUsagePct: 18.9,
      memoryUsageMb: 914,
      interfaces: ['eth0 (XDP)', 'kw_pri2 (TC Ingress/Egress)', 'kw_pri3'],
    }
  ]);

  readonly blacklistedIps = signal<string[]>([
    '203.0.113.19',
    '198.51.100.99',
    '192.0.2.144'
  ]);

  constructor() {
    // Start subtle live metrics simulation in browser
    if (typeof window !== 'undefined') {
      setInterval(() => {
        this.tickLiveMetrics();
      }, 3000);
    }
  }

  private tickLiveMetrics(): void {
    this.metrics.update(m => {
      const deltaPackets = Math.floor(Math.random() * 400) + 1200;
      const deltaBytes = deltaPackets * 840;
      const deltaDrops = Math.random() > 0.6 ? Math.floor(Math.random() * 6) + 1 : 0;
      return {
        ...m,
        packetsTotal: m.packetsTotal + deltaPackets,
        bytesTotal: m.bytesTotal + deltaBytes,
        dropsTotal: m.dropsTotal + deltaDrops,
        packetsPerSec: Math.floor(13800 + Math.random() * 800),
        dropsPerSec: 20 + deltaDrops,
        latencyP95Us: +(4.1 + Math.random() * 0.4).toFixed(1),
        latencyP99Us: +(8.5 + Math.random() * 0.5).toFixed(1),
      };
    });
  }

  addBlacklistIp(ip: string): void {
    if (ip && !this.blacklistedIps().includes(ip)) {
      this.blacklistedIps.update(list => [ip, ...list]);
    }
  }

  removeBlacklistIp(ip: string): void {
    this.blacklistedIps.update(list => list.filter(item => item !== ip));
  }
}
