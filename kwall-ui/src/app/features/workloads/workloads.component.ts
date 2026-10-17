import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { KwallDataService } from '../../core/services/kwall-data.service';

@Component({
  selector: 'app-workloads',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="space-y-6">
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 class="text-2xl font-bold tracking-tight text-white flex items-center gap-3">
            <span>Workload Identities & Node Topology</span>
            <span class="text-xs px-2.5 py-1 rounded-full bg-cyan-950/80 text-cyan-400 border border-cyan-800 font-mono font-medium">
              kw_endpoints BPF Map
            </span>
          </h1>
          <p class="text-slate-400 text-sm mt-1">
            Deterministic numerical identity allocation (u32) mapped to Kubernetes Pod IP, netkit ifindex, and namespaces.
          </p>
        </div>
      </div>

      <!-- Workloads Table -->
      <div class="glass-panel rounded-2xl overflow-hidden border border-slate-800">
        <div class="p-4 bg-slate-900/60 border-b border-slate-800 flex items-center justify-between">
          <div class="flex items-center gap-2">
            <span class="w-2 h-2 rounded-full bg-cyan-400"></span>
            <h2 class="text-sm font-semibold text-white">Active Workload Endpoints</h2>
          </div>
          <span class="text-xs font-mono text-slate-400">{{ data.workloads().length }} Pods Bound</span>
        </div>

        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs font-mono">
            <thead class="bg-slate-900/90 text-slate-400 border-b border-slate-800">
              <tr>
                <th class="py-3 px-4">IDENTITY ID</th>
                <th class="py-3 px-4">POD NAME</th>
                <th class="py-3 px-4">NAMESPACE</th>
                <th class="py-3 px-4">IP ADDRESS</th>
                <th class="py-3 px-4">NETKIT IFINDEX</th>
                <th class="py-3 px-4">HOST NODE</th>
                <th class="py-3 px-4">POD UID</th>
                <th class="py-3 px-4">STATUS</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800/60">
              @for (w of data.workloads(); track w.identityId) {
                <tr class="hover:bg-slate-900/40 transition">
                  <td class="py-3 px-4 text-cyan-400 font-bold">
                    {{ w.identityId }}
                  </td>
                  <td class="py-3 px-4 text-white font-sans font-medium">
                    {{ w.podName }}
                  </td>
                  <td class="py-3 px-4 text-slate-400">
                    <span class="px-2 py-0.5 rounded bg-slate-800/80 text-slate-300">
                      {{ w.namespace }}
                    </span>
                  </td>
                  <td class="py-3 px-4 text-slate-200">
                    {{ w.ip }}
                  </td>
                  <td class="py-3 px-4 text-slate-400">
                    kw_pri{{ w.ifindex }} (idx: {{ w.ifindex }})
                  </td>
                  <td class="py-3 px-4 text-slate-300">
                    {{ w.node }}
                  </td>
                  <td class="py-3 px-4 text-slate-500 text-[10px]">
                    {{ w.podUid.substring(0, 16) }}...
                  </td>
                  <td class="py-3 px-4">
                    <span class="px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-800 font-semibold text-[10px]">
                      {{ w.status }}
                    </span>
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      </div>

      <!-- Node Details Grid -->
      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        @for (node of data.nodes(); track node.name) {
          <div class="glass-panel p-5 rounded-2xl border border-slate-800 space-y-4">
            <div class="flex items-center justify-between border-b border-slate-800/80 pb-3">
              <div>
                <h3 class="text-base font-bold text-white">{{ node.name }}</h3>
                <p class="text-xs text-slate-400 font-mono mt-0.5">{{ node.kernelVersion }}</p>
              </div>
              <span class="px-2.5 py-1 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800 text-xs font-mono font-medium">
                {{ node.ebpfStatus }}
              </span>
            </div>

            <div class="grid grid-cols-3 gap-3 text-xs font-mono">
              <div class="p-3 rounded-xl bg-slate-900/60 border border-slate-800/80">
                <span class="text-slate-500 block">Netkit Status</span>
                <span class="text-cyan-400 font-semibold text-sm mt-1 block">{{ node.netkitStatus }}</span>
              </div>
              <div class="p-3 rounded-xl bg-slate-900/60 border border-slate-800/80">
                <span class="text-slate-500 block">CPU Load</span>
                <span class="text-slate-200 font-semibold text-sm mt-1 block">{{ node.cpuUsagePct }}%</span>
              </div>
              <div class="p-3 rounded-xl bg-slate-900/60 border border-slate-800/80">
                <span class="text-slate-500 block">BPF Memory</span>
                <span class="text-slate-200 font-semibold text-sm mt-1 block">{{ node.memoryUsageMb }} MB</span>
              </div>
            </div>

            <div class="space-y-1.5 text-xs">
              <span class="text-slate-400 font-medium">Kernel Attached Netdevs:</span>
              <div class="flex flex-wrap gap-1.5">
                @for (iface of node.interfaces; track iface) {
                  <span class="px-2 py-1 rounded bg-slate-900 border border-slate-800 text-cyan-400 font-mono text-[11px]">
                    {{ iface }}
                  </span>
                }
              </div>
            </div>
          </div>
        }
      </div>
    </div>
  `
})
export class WorkloadsComponent {
  readonly data = inject(KwallDataService);
}
