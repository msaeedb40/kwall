export interface NodeStatus {
  nodeName: string;
  kernelVersion: string;
  ebpfReady: boolean;
  netkitActive: boolean;
  lsmActive: boolean;
  activeInterfaces: string[];
  totalPackets: number;
  totalBytes: number;
  droppedPackets: number;
  activeEndpoints: number;
  enforcedPolicies: number;
  p95LatencyUs: number;
  p99LatencyUs: number;
}

export interface FlowRecord {
  id: string;
  timestamp: string;
  srcIdentity: number;
  dstIdentity: number;
  srcPod: string;
  dstPod: string;
  namespace: string;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: 'TCP' | 'UDP' | 'ICMP';
  direction: 'INGRESS' | 'EGRESS';
  verdict: 'PASS' | 'DROP' | 'REDIRECT';
  dropReason?: string;
  bytes: number;
  packets: number;
}

export interface SecurityAlert {
  id: string;
  timestamp: string;
  type: 'SYN Flood' | 'Port Scan' | 'Untrusted Executable' | 'DNS Tunneling' | 'Container Escape';
  severity: 'Info' | 'Low' | 'Medium' | 'High' | 'Critical';
  identityId: number;
  podName: string;
  namespace: string;
  sourceIp: string;
  description: string;
  blocked: boolean;
}

export interface PolicyRule {
  id: string;
  name: string;
  namespace: string;
  targetApp: string;
  ingressRules: {
    from: string[];
    ports: { port: number; protocol: string }[];
    action: 'Allow' | 'Deny';
  }[];
  egressRules: {
    to: string[];
    ports: { port: number; protocol: string }[];
    action: 'Allow' | 'Deny';
  }[];
  state: 'Active' | 'Draft' | 'Disabled';
  activeNodes: number;
}

export interface EbpfMapInfo {
  name: string;
  type: string;
  maxEntries: number;
  currentEntries: number;
  keySize: number;
  valueSize: number;
  description: string;
}
