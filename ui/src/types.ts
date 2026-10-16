// Domain interfaces and types for KWALL Dataplane & Runtime Security Platform

export type FlowVerdict = 'PASS' | 'DROP' | 'REDIRECT';
export type FlowProtocol = 'TCP' | 'UDP' | 'ICMP';
export type FlowDirection = 'INGRESS' | 'EGRESS';

export type AlertSeverity = 'Info' | 'Low' | 'Medium' | 'High' | 'Critical';
export type AlertCategory = 'SYN Flood' | 'Port Scan' | 'Untrusted Executable' | 'DNS Tunneling' | 'Container Escape';

export type StreamConnectionStatus = 'CONNECTING' | 'CONNECTED' | 'RECONNECTING' | 'OFFLINE' | 'STREAMING';

export interface IKwallNodeStatus {
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

export interface IKwallFlowRecord {
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
  protocol: FlowProtocol;
  direction: FlowDirection;
  verdict: FlowVerdict;
  dropReason?: string;
  bytes: number;
  packets: number;
}

export interface IKwallSecurityAlert {
  id: string;
  timestamp: string;
  type: AlertCategory;
  severity: AlertSeverity;
  identityId: number;
  podName: string;
  namespace: string;
  sourceIp: string;
  description: string;
  blocked: boolean;
}

export interface IPortRule {
  port: number;
  protocol: string;
}

export interface IIngressRule {
  from: string[];
  ports: IPortRule[];
  action: 'Allow' | 'Deny';
}

export interface IEgressRule {
  to: string[];
  ports: IPortRule[];
  action: 'Allow' | 'Deny';
}

export interface IKwallPolicyRule {
  id: string;
  name: string;
  namespace: string;
  targetApp: string;
  ingressRules: IIngressRule[];
  egressRules: IEgressRule[];
  state: 'Active' | 'Draft' | 'Disabled';
  activeNodes: number;
}

export interface IKwallEbpfMap {
  name: string;
  type: string;
  maxEntries: number;
  currentEntries: number;
  keySize: number;
  valueSize: number;
  description: string;
}

export interface IKwallBlacklistEntry {
  ip: string;
  reason: string;
  timestamp: string;
  packetsDropped: number;
}

export interface ICompiledBpfRule {
  mapName: string;
  keyRepresentation: string;
  valueRepresentation: string;
  verificationStatus: 'VERIFIED_ACTIVE' | 'DEFAULT_DENY_FALLTHROUGH' | 'PENDING_MAP_INSERTION';
}

export interface IKwallPolicyCompilationResult {
  policyId: string;
  ruleCount: number;
  compilationLatencyMs: number;
  bpfRules: ICompiledBpfRule[];
}

export interface IKwallApiConfig {
  baseUrl: string;
  wsUrl: string;
  streamIntervalMs: number;
  reconnectAttempts: number;
}
