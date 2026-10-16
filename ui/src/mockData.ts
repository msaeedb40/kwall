import type { EbpfMapInfo, FlowRecord, NodeStatus, PolicyRule, SecurityAlert } from './types';

export const initialNodeStatus: NodeStatus = {
  nodeName: 'k8s-node-worker-01',
  kernelVersion: 'Linux 6.8.0-45-generic #45-Ubuntu (BTF + netkit + BPF LSM)',
  ebpfReady: true,
  netkitActive: true,
  lsmActive: true,
  activeInterfaces: ['eth0', 'kw_pri4f9b', 'kw_pri81ac', 'kw_pri92de'],
  totalPackets: 18459203,
  totalBytes: 24918290412,
  droppedPackets: 12492,
  activeEndpoints: 148,
  enforcedPolicies: 24,
  p95LatencyUs: 1.4,
  p99LatencyUs: 2.8,
};

export const initialFlows: FlowRecord[] = [
  {
    id: 'fl-1001',
    timestamp: '10:45:01.420',
    srcIdentity: 1042,
    dstIdentity: 1045,
    srcPod: 'frontend-67d4f9b87-q8k92',
    dstPod: 'api-gateway-55cb89d4f-m2k10',
    namespace: 'production',
    srcIp: '10.244.1.42',
    dstIp: '10.244.1.45',
    srcPort: 48920,
    dstPort: 8080,
    protocol: 'TCP',
    direction: 'EGRESS',
    verdict: 'PASS',
    bytes: 2840,
    packets: 4,
  },
  {
    id: 'fl-1002',
    timestamp: '10:45:01.680',
    srcIdentity: 1045,
    dstIdentity: 1099,
    srcPod: 'api-gateway-55cb89d4f-m2k10',
    dstPod: 'payment-processor-78f99-x7811',
    namespace: 'production',
    srcIp: '10.244.1.45',
    dstIp: '10.244.2.19',
    srcPort: 52104,
    dstPort: 443,
    protocol: 'TCP',
    direction: 'EGRESS',
    verdict: 'PASS',
    bytes: 1420,
    packets: 2,
  },
  {
    id: 'fl-1003',
    timestamp: '10:45:02.110',
    srcIdentity: 2, // IDENTITY_WORLD
    dstIdentity: 1042,
    srcPod: 'external-client',
    dstPod: 'frontend-67d4f9b87-q8k92',
    namespace: 'production',
    srcIp: '198.51.100.24',
    dstIp: '10.244.1.42',
    srcPort: 61922,
    dstPort: 22,
    protocol: 'TCP',
    direction: 'INGRESS',
    verdict: 'DROP',
    dropReason: 'PolicyDeny (SSH not permitted)',
    bytes: 64,
    packets: 1,
  },
  {
    id: 'fl-1004',
    timestamp: '10:45:02.350',
    srcIdentity: 1001,
    dstIdentity: 1088,
    srcPod: 'monitoring-prometheus-0',
    dstPod: 'kube-state-metrics-77d9c-p019',
    namespace: 'monitoring',
    srcIp: '10.244.0.12',
    dstIp: '10.244.1.88',
    srcPort: 41920,
    dstPort: 8080,
    protocol: 'TCP',
    direction: 'INGRESS',
    verdict: 'PASS',
    bytes: 8490,
    packets: 12,
  },
  {
    id: 'fl-1005',
    timestamp: '10:45:02.890',
    srcIdentity: 2, // Blacklisted
    dstIdentity: 1042,
    srcPod: 'botnet-scanner',
    dstPod: 'frontend-67d4f9b87-q8k92',
    namespace: 'production',
    srcIp: '203.0.113.89',
    dstIp: '10.244.1.42',
    srcPort: 44102,
    dstPort: 443,
    protocol: 'TCP',
    direction: 'INGRESS',
    verdict: 'DROP',
    dropReason: 'BlacklistedIP (Early XDP Drop)',
    bytes: 54,
    packets: 1,
  },
];

export const initialSecurityAlerts: SecurityAlert[] = [
  {
    id: 'sec-001',
    timestamp: '10:44:50',
    type: 'SYN Flood',
    severity: 'Critical',
    identityId: 2,
    podName: 'frontend-67d4f9b87-q8k92',
    namespace: 'production',
    sourceIp: '203.0.113.89',
    description: 'Volumetric SYN flood exceeded 10,000 pps threshold. Source IP automatically committed to KW_IP_BLACKLIST for XDP drop.',
    blocked: true,
  },
  {
    id: 'sec-002',
    timestamp: '10:42:15',
    type: 'Port Scan',
    severity: 'High',
    identityId: 1090,
    podName: 'compromised-dev-pod-66c',
    namespace: 'dev-sandbox',
    sourceIp: '10.244.3.44',
    description: 'Lateral reconnaissance scan detected across 28 distinct internal ports in 200ms window.',
    blocked: true,
  },
  {
    id: 'sec-003',
    timestamp: '10:38:02',
    type: 'Untrusted Executable',
    severity: 'Critical',
    identityId: 1045,
    podName: 'api-gateway-55cb89d4f-m2k10',
    namespace: 'production',
    sourceIp: '10.244.1.45',
    description: 'BPF LSM intercepted execution of unapproved binary (/tmp/xmrig-miner) by PID 49219. Execution blocked with -EPERM.',
    blocked: true,
  },
  {
    id: 'sec-004',
    timestamp: '10:29:40',
    type: 'DNS Tunneling',
    severity: 'Medium',
    identityId: 1033,
    podName: 'batch-worker-44d-j99k',
    namespace: 'data-pipeline',
    sourceIp: '10.244.2.110',
    description: 'Anomalous base64 encoded TXT record queries exceeding 256 bytes payload size.',
    blocked: false,
  },
];

export const initialPolicies: PolicyRule[] = [
  {
    id: 'pol-01',
    name: 'kwall-protect-production-frontend',
    namespace: 'production',
    targetApp: 'frontend',
    ingressRules: [
      {
        from: ['ingress-nginx', 'world'],
        ports: [{ port: 80, protocol: 'TCP' }, { port: 443, protocol: 'TCP' }],
        action: 'Allow',
      },
    ],
    egressRules: [
      {
        to: ['api-gateway', 'kube-dns'],
        ports: [{ port: 8080, protocol: 'TCP' }, { port: 53, protocol: 'UDP' }],
        action: 'Allow',
      },
    ],
    state: 'Active',
    activeNodes: 8,
  },
  {
    id: 'pol-02',
    name: 'kwall-isolate-payment-tier',
    namespace: 'production',
    targetApp: 'payment-processor',
    ingressRules: [
      {
        from: ['api-gateway'],
        ports: [{ port: 443, protocol: 'TCP' }],
        action: 'Allow',
      },
    ],
    egressRules: [
      {
        to: ['stripe-gateway-external', 'internal-ledger-db'],
        ports: [{ port: 443, protocol: 'TCP' }, { port: 5432, protocol: 'TCP' }],
        action: 'Allow',
      },
    ],
    state: 'Active',
    activeNodes: 4,
  },
  {
    id: 'pol-03',
    name: 'kwall-strict-default-deny',
    namespace: 'production',
    targetApp: '*',
    ingressRules: [],
    egressRules: [],
    state: 'Active',
    activeNodes: 8,
  },
];

export const ebpfMapsList: EbpfMapInfo[] = [
  {
    name: 'kw_endpoints',
    type: 'BPF_MAP_TYPE_HASH',
    maxEntries: 65536,
    currentEntries: 148,
    keySize: 4,
    valueSize: 32,
    description: 'Maps IPv4/IPv6 address to security EndpointIdentity struct',
  },
  {
    name: 'kw_policies',
    type: 'BPF_MAP_TYPE_HASH',
    maxEntries: 65536,
    currentEntries: 312,
    keySize: 12,
    valueSize: 16,
    description: 'Compiled L3/L4/Identity policy keys to action verdicts',
  },
  {
    name: 'kw_conntrack',
    type: 'BPF_MAP_TYPE_LRU_HASH',
    maxEntries: 262144,
    currentEntries: 14209,
    keySize: 40,
    valueSize: 32,
    description: 'Stateful bidirectional TCP/UDP flow connection tracking table',
  },
  {
    name: 'kw_ip_blacklist',
    type: 'BPF_MAP_TYPE_HASH',
    maxEntries: 65536,
    currentEntries: 42,
    keySize: 4,
    valueSize: 1,
    description: 'Wire-speed XDP early drop blacklist for DDoS attackers',
  },
  {
    name: 'kw_flow_events',
    type: 'BPF_MAP_TYPE_RINGBUF',
    maxEntries: 1048576, // 1MB
    currentEntries: 128,
    keySize: 0,
    valueSize: 72,
    description: 'Lockless kernel-to-userspace flow ring buffer',
  },
  {
    name: 'kw_sec_events',
    type: 'BPF_MAP_TYPE_RINGBUF',
    maxEntries: 524288, // 512KB
    currentEntries: 4,
    keySize: 0,
    valueSize: 112,
    description: 'Lockless high-priority security and threat alert ring buffer',
  },
];

export function generateRandomFlow(): FlowRecord {
  const pods = [
    { name: 'frontend-67d4f9b87', id: 1042, ip: '10.244.1.42', ns: 'production' },
    { name: 'api-gateway-55cb8', id: 1045, ip: '10.244.1.45', ns: 'production' },
    { name: 'order-service-77a', id: 1060, ip: '10.244.2.14', ns: 'production' },
    { name: 'redis-cache-0', id: 1070, ip: '10.244.2.55', ns: 'production' },
    { name: 'ingress-nginx', id: 1010, ip: '10.244.0.5', ns: 'ingress-nginx' },
    { name: 'world-client', id: 2, ip: '198.51.100.99', ns: 'external' },
  ];

  const src = pods[Math.floor(Math.random() * pods.length)];
  let dst = pods[Math.floor(Math.random() * pods.length)];
  while (dst === src) {
    dst = pods[Math.floor(Math.random() * pods.length)];
  }

  const isDrop = Math.random() < 0.15;
  const ports = [80, 443, 8080, 6379, 5432, 22, 9090];
  const port = ports[Math.floor(Math.random() * ports.length)];
  const protos: ('TCP' | 'UDP')[] = ['TCP', 'TCP', 'TCP', 'UDP'];

  const now = new Date();
  const timeStr = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}.${String(now.getMilliseconds()).padStart(3, '0')}`;

  return {
    id: `fl-${Math.floor(1000 + Math.random() * 9000)}`,
    timestamp: timeStr,
    srcIdentity: src.id,
    dstIdentity: dst.id,
    srcPod: src.name,
    dstPod: dst.name,
    namespace: src.ns,
    srcIp: src.ip,
    dstIp: dst.ip,
    srcPort: Math.floor(30000 + Math.random() * 30000),
    dstPort: port,
    protocol: protos[Math.floor(Math.random() * protos.length)],
    direction: Math.random() > 0.5 ? 'INGRESS' : 'EGRESS',
    verdict: isDrop ? 'DROP' : 'PASS',
    dropReason: isDrop ? (port === 22 ? 'PolicyDeny (SSH blocked)' : 'PolicyDeny (Unauthorized cross-tier)') : undefined,
    bytes: Math.floor(200 + Math.random() * 4000),
    packets: Math.floor(1 + Math.random() * 8),
  };
}
