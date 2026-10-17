import { Component, inject } from '@angular/core';
import { CommonModule, DecimalPipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import { KwallDataService } from '../../core/services/kwall-data.service';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, DecimalPipe, RouterLink],
  template: `
    <div class="space-y-6">
      <!-- Title & Live Bar -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 class="text-2xl font-bold tracking-tight text-white flex items-center gap-3">
            <span>Cluster Dataplane Telemetry</span>
            <span class="text-xs px-2.5 py-1 rounded-full bg-emerald-950/80 text-emerald-400 border border-emerald-800 font-mono font-medium flex items-center gap-1.5">
              <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              Live Pipeline Active
            </span>
          </h1>
          <p class="text-slate-400 text-sm mt-1">
            Real-time eBPF XDP, TC, and netkit packet filtering across all cluster nodes.
          </p>
        </div>

        <div class="flex items-center gap-3">
          <a
            routerLink="/flows"
            class="px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs font-medium flex items-center gap-2 transition"
          >
            <span>Live Flow Inspector</span>
            <svg class="w-4 h-4 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14 5l7 7m0 0l-7 7m7-7H3" />
            </svg>
          </a>
        </div>
      </div>

      <!-- Stat Metric Cards -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <!-- Packets Total -->
        <div class="glass-panel p-5 rounded-2xl relative overflow-hidden group">
          <div class="absolute -right-4 -bottom-4 w-24 h-24 bg-cyan-500/10 rounded-full blur-xl group-hover:bg-cyan-500/20 transition-all"></div>
          <div class="text-xs font-mono text-cyan-400 font-medium">TOTAL PACKETS</div>
          <div class="text-2xl font-bold text-white mt-1 font-mono tracking-tight">
            {{ data.metrics().packetsTotal | number }}
          </div>
          <div class="flex items-center justify-between text-xs text-slate-400 mt-3 pt-3 border-t border-slate-800">
            <span>Throughput</span>
            <span class="text-cyan-400 font-mono font-semibold">{{ data.metrics().packetsPerSec | number }} pps</span>
          </div>
        </div>

        <!-- Conntrack Entries -->
        <div class="glass-panel p-5 rounded-2xl relative overflow-hidden group">
          <div class="absolute -right-4 -bottom-4 w-24 h-24 bg-emerald-500/10 rounded-full blur-xl group-hover:bg-emerald-500/20 transition-all"></div>
          <div class="text-xs font-mono text-emerald-400 font-medium">ACTIVE CONNTRACK</div>
          <div class="text-2xl font-bold text-white mt-1 font-mono tracking-tight">
            {{ data.metrics().activeConntrack | number }}
          </div>
          <div class="flex items-center justify-between text-xs text-slate-400 mt-3 pt-3 border-t border-slate-800">
            <span>Table Utilization</span>
            <span class="text-emerald-400 font-mono font-semibold">12.8%</span>
          </div>
        </div>

        <!-- Latency -->
        <div class="glass-panel p-5 rounded-2xl relative overflow-hidden group">
          <div class="absolute -right-4 -bottom-4 w-24 h-24 bg-indigo-500/10 rounded-full blur-xl group-hover:bg-indigo-500/20 transition-all"></div>
          <div class="text-xs font-mono text-indigo-400 font-medium">DATAPLANE LATENCY</div>
          <div class="text-2xl font-bold text-white mt-1 font-mono tracking-tight flex items-baseline gap-2">
            <span>{{ data.metrics().latencyP95Us }}</span>
            <span class="text-xs font-normal text-slate-400">µs (P95)</span>
          </div>
          <div class="flex items-center justify-between text-xs text-slate-400 mt-3 pt-3 border-t border-slate-800">
            <span>P99 Worst-case</span>
            <span class="text-indigo-400 font-mono font-semibold">{{ data.metrics().latencyP99Us }} µs</span>
          </div>
        </div>

        <!-- Threats Blocked -->
        <div class="glass-panel p-5 rounded-2xl relative overflow-hidden group">
          <div class="absolute -right-4 -bottom-4 w-24 h-24 bg-rose-500/10 rounded-full blur-xl group-hover:bg-rose-500/20 transition-all"></div>
          <div class="text-xs font-mono text-rose-400 font-medium">THREATS INTERCEPTED</div>
          <div class="text-2xl font-bold text-white mt-1 font-mono tracking-tight">
            {{ data.metrics().threatsBlocked | number }}
          </div>
          <div class="flex items-center justify-between text-xs text-slate-400 mt-3 pt-3 border-t border-slate-800">
            <span>Early XDP Drops</span>
            <span class="text-rose-400 font-mono font-semibold">{{ data.metrics().dropsTotal | number }}</span>
          </div>
        </div>
      </div>

      <!-- Main Section: Threat Incidents & Active Nodes -->
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Live Threat Feed -->
        <div class="lg:col-span-2 glass-panel rounded-2xl p-5 flex flex-col justify-between">
          <div>
            <div class="flex items-center justify-between mb-4">
              <div class="flex items-center gap-2">
                <span class="w-2.5 h-2.5 rounded-full bg-rose-500 animate-ping"></span>
                <h2 class="text-base font-semibold text-white">Multi-Layer Threat Detections</h2>
              </div>
              <a routerLink="/security" class="text-xs text-cyan-400 hover:text-cyan-300 font-medium">View Security Hub →</a>
            </div>

            <div class="space-y-3">
              @for (alert of data.alerts(); track alert.id) {
                <div class="p-3.5 rounded-xl bg-slate-900/70 border border-slate-800/80 hover:border-slate-700 transition">
                  <div class="flex items-center justify-between mb-1.5">
                    <div class="flex items-center gap-2">
                      <span
                        [ngClass]="{
                          'bg-rose-950/80 text-rose-400 border-rose-800': alert.severity === 'Critical',
                          'bg-amber-950/80 text-amber-400 border-amber-800': alert.severity === 'High',
                          'bg-blue-950/80 text-blue-400 border-blue-800': alert.severity === 'Medium',
                          'bg-slate-800 text-slate-300 border-slate-700': alert.severity === 'Low'
                        }"
                        class="text-xs px-2 py-0.5 rounded border font-semibold font-mono"
                      >
                        {{ alert.severity }}
                      </span>
                      <span class="text-sm font-semibold text-slate-100">{{ alert.eventType }}</span>
                    </div>
                    <span class="text-xs font-mono text-slate-500">{{ alert.timestamp }}</span>
                  </div>

                  <p class="text-xs text-slate-300 mt-1">{{ alert.details }}</p>

                  <div class="flex items-center gap-4 text-xs font-mono text-slate-400 mt-2 pt-2 border-t border-slate-800/60">
                    <div><span class="text-slate-500">SRC:</span> <span class="text-slate-200">{{ alert.source }}</span></div>
                    <div><span class="text-slate-500">TGT:</span> <span class="text-slate-200">{{ alert.target }}</span></div>
                  </div>
                </div>
              }
            </div>
          </div>
        </div>

        <!-- Node & Kernel Status -->
        <div class="glass-panel rounded-2xl p-5 flex flex-col justify-between">
          <div>
            <div class="flex items-center justify-between mb-4">
              <h2 class="text-base font-semibold text-white">Cluster Nodes</h2>
              <span class="text-xs font-mono text-slate-400">{{ data.nodes().length }} Nodes</span>
            </div>

            <div class="space-y-3">
              @for (node of data.nodes(); track node.name) {
                <div class="p-3.5 rounded-xl bg-slate-900/70 border border-slate-800">
                  <div class="flex items-center justify-between">
                    <span class="font-semibold text-white text-sm">{{ node.name }}</span>
                    <span class="text-xs px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-mono">
                      {{ node.ebpfStatus }}
                    </span>
                  </div>

                  <div class="text-xs text-slate-400 mt-1.5 font-mono">
                    {{ node.kernelVersion }}
                  </div>

                  <div class="mt-3 grid grid-cols-2 gap-2 text-xs font-mono">
                    <div class="p-2 rounded bg-slate-950/60 border border-slate-800/80">
                      <div class="text-slate-500">CPU Usage</div>
                      <div class="text-slate-200 font-semibold mt-0.5">{{ node.cpuUsagePct }}%</div>
                    </div>
                    <div class="p-2 rounded bg-slate-950/60 border border-slate-800/80">
                      <div class="text-slate-500">eBPF Mem</div>
                      <div class="text-slate-200 font-semibold mt-0.5">{{ node.memoryUsageMb }} MB</div>
                    </div>
                  </div>

                  <div class="mt-2.5 text-xs text-slate-500">
                    Attached Interfaces:
                    <div class="flex flex-wrap gap-1 mt-1">
                      @for (iface of node.interfaces; track iface) {
                        <span class="px-1.5 py-0.5 rounded bg-slate-800/80 text-cyan-400 font-mono text-[10px]">
                          {{ iface }}
                        </span>
                      }
                    </div>
                  </div>
                </div>
              }
            </div>
          </div>

          <div class="mt-4 p-3 rounded-xl bg-cyan-950/30 border border-cyan-800/40 text-xs text-cyan-300">
            <span class="font-bold">Aya netkit driver:</span> zero-copy skb redirect enabled on primary/peer interfaces.
          </div>
        </div>
      </div>
    </div>
  `
})
export class DashboardComponent {
  readonly data = inject(KwallDataService);
}
