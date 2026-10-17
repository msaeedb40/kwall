import { Component, inject, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { KwallDataService, FlowRecord } from '../../core/services/kwall-data.service';

@Component({
  selector: 'app-flows',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="space-y-6">
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 class="text-2xl font-bold tracking-tight text-white flex items-center gap-3">
            <span>Netkit Live Flow Telemetry</span>
            <span class="text-xs px-2.5 py-1 rounded-full bg-cyan-950/80 text-cyan-400 border border-cyan-800 font-mono font-medium">
              eBPF Ring Buffer
            </span>
          </h1>
          <p class="text-slate-400 text-sm mt-1">
            Real-time packet inspection streams forwarded directly from Linux 6.8+ netkit hooks.
          </p>
        </div>

        <div class="flex items-center gap-2">
          <button
            (click)="simulateTraffic()"
            class="px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-lg shadow-cyan-600/20 transition flex items-center gap-2"
          >
            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
            </svg>
            Generate Flow Event
          </button>
        </div>
      </div>

      <!-- Filters & Search -->
      <div class="glass-panel p-4 rounded-xl flex flex-wrap items-center justify-between gap-4">
        <div class="flex flex-wrap items-center gap-3">
          <div class="relative">
            <input
              type="text"
              [(ngModel)]="searchQuery"
              placeholder="Filter by IP, workload, or port..."
              class="w-72 bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div class="flex items-center rounded-lg bg-slate-900 p-1 border border-slate-800 text-xs">
            <button
              (click)="selectedAction.set('ALL')"
              [class.bg-slate-800]="selectedAction() === 'ALL'"
              [class.text-white]="selectedAction() === 'ALL'"
              class="px-2.5 py-1 rounded text-slate-400 hover:text-white transition"
            >
              All Actions
            </button>
            <button
              (click)="selectedAction.set('PASS')"
              [class.bg-emerald-950]="selectedAction() === 'PASS'"
              [class.text-emerald-400]="selectedAction() === 'PASS'"
              class="px-2.5 py-1 rounded text-slate-400 hover:text-white transition"
            >
              PASS
            </button>
            <button
              (click)="selectedAction.set('DROP')"
              [class.bg-rose-950]="selectedAction() === 'DROP'"
              [class.text-rose-400]="selectedAction() === 'DROP'"
              class="px-2.5 py-1 rounded text-slate-400 hover:text-white transition"
            >
              DROP
            </button>
          </div>

          <div class="flex items-center rounded-lg bg-slate-900 p-1 border border-slate-800 text-xs">
            <button
              (click)="selectedProtocol.set('ALL')"
              [class.bg-slate-800]="selectedProtocol() === 'ALL'"
              [class.text-white]="selectedProtocol() === 'ALL'"
              class="px-2.5 py-1 rounded text-slate-400 hover:text-white transition"
            >
              All Proto
            </button>
            <button
              (click)="selectedProtocol.set('TCP')"
              [class.bg-cyan-950]="selectedProtocol() === 'TCP'"
              [class.text-cyan-400]="selectedProtocol() === 'TCP'"
              class="px-2.5 py-1 rounded text-slate-400 hover:text-white transition"
            >
              TCP
            </button>
            <button
              (click)="selectedProtocol.set('UDP')"
              [class.bg-cyan-950]="selectedProtocol() === 'UDP'"
              [class.text-cyan-400]="selectedProtocol() === 'UDP'"
              class="px-2.5 py-1 rounded text-slate-400 hover:text-white transition"
            >
              UDP
            </button>
          </div>
        </div>

        <div class="text-xs font-mono text-slate-400">
          Showing <span class="text-white font-semibold">{{ filteredFlows().length }}</span> flows
        </div>
      </div>

      <!-- Flows Table -->
      <div class="glass-panel rounded-2xl overflow-hidden border border-slate-800">
        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs">
            <thead class="bg-slate-900/80 text-slate-400 border-b border-slate-800 font-mono">
              <tr>
                <th class="py-3 px-4">TIMESTAMP</th>
                <th class="py-3 px-4">SOURCE ENDPOINT</th>
                <th class="py-3 px-4">DESTINATION ENDPOINT</th>
                <th class="py-3 px-4">PROTO / DIR</th>
                <th class="py-3 px-4">VOLUMETRICS</th>
                <th class="py-3 px-4">POLICY / RULE</th>
                <th class="py-3 px-4">VERDICT</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800/60 font-mono">
              @for (flow of filteredFlows(); track flow.id) {
                <tr class="hover:bg-slate-900/40 transition">
                  <td class="py-3 px-4 text-slate-400">
                    {{ flow.timestamp }}
                  </td>
                  <td class="py-3 px-4">
                    <div class="text-white font-sans font-medium">{{ flow.srcWorkload }}</div>
                    <div class="text-slate-400 text-[11px]">{{ flow.srcIp }}:{{ flow.srcPort }} <span class="text-cyan-400">(id:{{ flow.srcIdentity }})</span></div>
                  </td>
                  <td class="py-3 px-4">
                    <div class="text-white font-sans font-medium">{{ flow.dstWorkload }}</div>
                    <div class="text-slate-400 text-[11px]">{{ flow.dstIp }}:{{ flow.dstPort }} <span class="text-cyan-400">(id:{{ flow.dstIdentity }})</span></div>
                  </td>
                  <td class="py-3 px-4">
                    <div class="flex items-center gap-1.5">
                      <span class="px-1.5 py-0.5 rounded bg-slate-800 text-slate-200 text-[10px]">
                        {{ flow.protocol }}
                      </span>
                      <span class="text-slate-500 text-[11px]">{{ flow.direction }}</span>
                    </div>
                  </td>
                  <td class="py-3 px-4">
                    <div class="text-slate-200">{{ flow.packets }} pkts</div>
                    <div class="text-slate-500 text-[10px]">{{ (flow.bytes / 1024).toFixed(1) }} KB</div>
                  </td>
                  <td class="py-3 px-4">
                    @if (flow.policyId > 0) {
                      <span class="text-cyan-400">pol-{{ flow.policyId }}</span>
                    } @else {
                      <span class="text-slate-600">Default</span>
                    }
                  </td>
                  <td class="py-3 px-4">
                    @if (flow.action === 'PASS') {
                      <span class="px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-800 font-semibold text-[10px]">
                        PASS
                      </span>
                    } @else {
                      <div class="flex flex-col items-start gap-0.5">
                        <span class="px-2 py-0.5 rounded bg-rose-950/80 text-rose-400 border border-rose-800 font-semibold text-[10px]">
                          DROP
                        </span>
                        <span class="text-[10px] text-rose-400/80">{{ flow.dropReason || 'PolicyDeny' }}</span>
                      </div>
                    }
                  </td>
                </tr>
              } @empty {
                <tr>
                  <td colspan="7" class="py-8 text-center text-slate-500 font-sans">
                    No matching flows found with current filters.
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `
})
export class FlowsComponent {
  readonly data = inject(KwallDataService);

  searchQuery = '';
  selectedAction = signal<'ALL' | 'PASS' | 'DROP'>('ALL');
  selectedProtocol = signal<'ALL' | 'TCP' | 'UDP'>('ALL');

  filteredFlows = computed(() => {
    const q = this.searchQuery.toLowerCase().trim();
    const action = this.selectedAction();
    const proto = this.selectedProtocol();

    return this.data.flows().filter(f => {
      if (action !== 'ALL' && f.action !== action) return false;
      if (proto !== 'ALL' && f.protocol !== proto) return false;
      if (q) {
        const matchSrc = f.srcIp.toLowerCase().includes(q) || f.srcWorkload.toLowerCase().includes(q);
        const matchDst = f.dstIp.toLowerCase().includes(q) || f.dstWorkload.toLowerCase().includes(q);
        const matchPort = f.srcPort.toString().includes(q) || f.dstPort.toString().includes(q);
        if (!matchSrc && !matchDst && !matchPort) return false;
      }
      return true;
    });
  });

  simulateTraffic(): void {
    const isDrop = Math.random() > 0.65;
    const newFlow: FlowRecord = {
      id: 'fl-' + Date.now(),
      timestamp: new Date().toLocaleTimeString() + '.' + Math.floor(Math.random() * 900 + 100),
      srcIdentity: Math.floor(Math.random() * 10) + 1040,
      srcWorkload: isDrop ? 'external-scanner' : 'checkout-svc-' + Math.floor(Math.random() * 10),
      srcIp: isDrop ? '198.51.100.' + Math.floor(Math.random() * 200 + 1) : '10.244.1.' + Math.floor(Math.random() * 200 + 1),
      srcPort: Math.floor(Math.random() * 30000 + 20000),
      dstIdentity: 1055,
      dstWorkload: 'vault-auth-db-0',
      dstIp: '10.244.2.99',
      dstPort: 5432,
      protocol: 'TCP',
      direction: 'Ingress',
      action: isDrop ? 'DROP' : 'PASS',
      dropReason: isDrop ? 'PolicyDeny' : undefined,
      packets: Math.floor(Math.random() * 12) + 1,
      bytes: Math.floor(Math.random() * 1000) + 60,
      policyId: isDrop ? 0 : 101,
    };

    this.data.flows.update(current => [newFlow, ...current.slice(0, 49)]);
  }
}
