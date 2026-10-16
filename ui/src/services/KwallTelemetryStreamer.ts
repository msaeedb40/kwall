import type {
  IKwallTelemetryStreamer,
  ITelemetrySubscription,
} from './interfaces';
import type {
  IKwallFlowRecord,
  StreamConnectionStatus,
} from '../types';

export class KwallTelemetryStreamer implements IKwallTelemetryStreamer {
  private readonly wsUrl: string;
  private socket: WebSocket | null = null;
  private status: StreamConnectionStatus = 'OFFLINE';
  private subscribers: Set<(flow: IKwallFlowRecord) => void> = new Set();
  private statusSubscribers: Set<(status: StreamConnectionStatus) => void> = new Set();
  private isActive: boolean = false;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private retryCount: number = 0;
  private readonly maxRetries: number = 5;

  public constructor(wsUrl: string = 'ws://localhost:8080/api/v1/ws') {
    this.wsUrl = wsUrl;
  }

  public getConnectionStatus(): StreamConnectionStatus {
    return this.status;
  }

  public subscribe(
    onFlow: (flow: IKwallFlowRecord) => void,
    onStatusChange?: (status: StreamConnectionStatus) => void
  ): ITelemetrySubscription {
    this.subscribers.add(onFlow);
    if (onStatusChange) {
      this.statusSubscribers.add(onStatusChange);
      onStatusChange(this.status);
    }

    return {
      unsubscribe: () => {
        this.subscribers.delete(onFlow);
        if (onStatusChange) {
          this.statusSubscribers.delete(onStatusChange);
        }
      },
    };
  }

  public start(): void {
    if (this.isActive) return;
    this.isActive = true;
    this.retryCount = 0;
    this.connect();
  }

  public stop(): void {
    this.isActive = false;
    this.clearReconnectTimer();
    this.cleanupSocket();
    this.updateStatus('OFFLINE');
  }

  private updateStatus(newStatus: StreamConnectionStatus): void {
    this.status = newStatus;
    for (const callback of this.statusSubscribers) {
      callback(newStatus);
    }
  }

  private connect(): void {
    if (typeof window === 'undefined') return;

    this.clearReconnectTimer();
    this.updateStatus(this.retryCount > 0 ? 'RECONNECTING' : 'CONNECTING');

    try {
      this.socket = new WebSocket(this.wsUrl);

      this.socket.onopen = () => {
        this.retryCount = 0;
        this.updateStatus('STREAMING');
      };

      this.socket.onmessage = (event: MessageEvent) => {
        try {
          const flow = JSON.parse(event.data as string) as IKwallFlowRecord;
          this.emitFlow(flow);
        } catch {
          // Ignore invalid frames
        }
      };

      this.socket.onerror = () => {
        this.cleanupSocket();
        this.scheduleReconnect();
      };

      this.socket.onclose = () => {
        this.cleanupSocket();
        if (this.isActive) {
          this.scheduleReconnect();
        }
      };
    } catch {
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect(): void {
    if (!this.isActive) return;

    if (this.retryCount < this.maxRetries) {
      this.retryCount++;
      const backoffMs = Math.min(1000 * Math.pow(2, this.retryCount), 10000);
      this.updateStatus('RECONNECTING');
      this.reconnectTimer = setTimeout(() => {
        this.connect();
      }, backoffMs);
    } else {
      this.updateStatus('OFFLINE');
    }
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  private cleanupSocket(): void {
    if (this.socket) {
      this.socket.onopen = null;
      this.socket.onmessage = null;
      this.socket.onerror = null;
      this.socket.onclose = null;
      try {
        this.socket.close();
      } catch {
        // no-op
      }
      this.socket = null;
    }
  }

  private emitFlow(flow: IKwallFlowRecord): void {
    for (const sub of this.subscribers) {
      sub(flow);
    }
  }
}
