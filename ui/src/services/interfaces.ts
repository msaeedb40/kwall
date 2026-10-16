import type {
  IKwallNodeStatus,
  IKwallEbpfMap,
  IKwallPolicyRule,
  IKwallSecurityAlert,
  IKwallBlacklistEntry,
  IKwallPolicyCompilationResult,
  IKwallFlowRecord,
  StreamConnectionStatus,
  IKwallApiConfig,
} from '../types';

export type {
  IKwallNodeStatus,
  IKwallEbpfMap,
  IKwallPolicyRule,
  IKwallSecurityAlert,
  IKwallBlacklistEntry,
  IKwallPolicyCompilationResult,
  IKwallFlowRecord,
  StreamConnectionStatus,
  IKwallApiConfig,
};

export interface IKwallApiClient {
  getConfig(): IKwallApiConfig;
  fetchNodeStatus(): Promise<IKwallNodeStatus>;
  fetchEbpfMaps(): Promise<IKwallEbpfMap[]>;
  fetchPolicies(): Promise<IKwallPolicyRule[]>;
  fetchThreatAlerts(): Promise<IKwallSecurityAlert[]>;
  fetchBlacklist(): Promise<IKwallBlacklistEntry[]>;
  addToBlacklist(ip: string, reason: string): Promise<IKwallBlacklistEntry>;
  removeFromBlacklist(ip: string): Promise<void>;
  compilePolicy(policy: IKwallPolicyRule): Promise<IKwallPolicyCompilationResult>;
}

export interface ITelemetrySubscription {
  unsubscribe(): void;
}

export interface IKwallTelemetryStreamer {
  subscribe(onFlow: (flow: IKwallFlowRecord) => void, onStatusChange?: (status: StreamConnectionStatus) => void): ITelemetrySubscription;
  getConnectionStatus(): StreamConnectionStatus;
  start(): void;
  stop(): void;
}
