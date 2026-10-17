import { Component, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { KwallDataService } from '../../core/services/kwall-data.service';

@Component({
  selector: 'app-security',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="space-y-6">
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 class="text-2xl font-bold tracking-tight text-white flex items-center gap-3">
            <span>Threat Defense & Policy Engine</span>
            <span class="text-xs px-2.5 py-1 rounded-full bg-rose-950/80 text-rose-400 border border-rose-800 font-mono font-medium">
              Multi-Layer Defense Active
            </span>
          </h1>
          <p class="text-slate-400 text-sm mt-1">
            Declarative Kubernetes CRD enforcement synchronized with Linux LSM, XDP, and TC eBPF maps.
          </p>
        </div>
      </div>

      <!-- Top Row: XDP Dynamic Blacklist & Threat Stats -->
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Dynamic eBPF Blacklist -->
        <div class="glass-panel p-5 rounded-2xl border border-slate-800 flex flex-col justify-between">
          <div>
            <div class="flex items-center justify-between mb-3">
              <h2 class="text-sm font-semibold text-white flex items-center gap-2">
                <span class="w-2 h-2 rounded-full bg-rose-500"></span>
                <span>eBPF XDP Hardware/Early Blacklist</span>
              </h2>
              <span class="text-xs font-mono text-cyan-400">kw_ip_blacklist map</span>
            </div>
            <p class="text-xs text-slate-400 mb-4">
              Packets from these IP addresses are dropped immediately at the XDP driver layer before kernel socket allocation.
            </p>

            <!-- Add IP input -->
            <div class="flex gap-2 mb-4">
              <input
                type="text"
                [(ngModel)]="newBlacklistIp"
                placeholder="e.g. 198.51.100.25"
                class="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
              />
              <button
                (click)="addIp()"
                class="px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold shadow-md transition"
              >
                Block IP
              </button>
            </div>

            <!-- Blacklisted IP list -->
            <div class="space-y-2 max-h-48 overflow-y-auto pr-1">
              @for (ip of data.blacklistedIps(); track ip) {
                <div class="flex items-center justify-between p-2 rounded-lg bg-slate-900/80 border border-slate-800/80 text-xs font-mono">
                  <div class="flex items-center gap-2">
                    <span class="w-1.5 h-1.5 rounded-full bg-rose-400"></span>
                    <span class="text-slate-200">{{ ip }}</span>
                    <span class="text-[10px] text-slate-500">(/32)</span>
                  </div>
                  <button
                    (click)="data.removeBlacklistIp(ip)"
                    class="text-slate-400 hover:text-rose-400 transition text-[11px] px-1.5 py-0.5 rounded hover:bg-slate-800"
                  >
                    Unblock
                  </button>
                </div>
              }
            </div>
          </div>

          <div class="mt-4 pt-3 border-t border-slate-800/80 text-[11px] text-slate-400 flex items-center justify-between">
            <span>Total Blocked IPs: <strong class="text-white">{{ data.blacklistedIps().length }}</strong></span>
            <span class="text-emerald-400">BPF Map Sync: OK</span>
          </div>
        </div>

        <!-- Security Detection Engine Overview -->
        <div class="lg:col-span-2 glass-panel p-5 rounded-2xl border border-slate-800">
          <div class="flex items-center justify-between mb-4">
            <h2 class="text-sm font-semibold text-white">Multi-Layer Threat Detectors</h2>
            <span class="text-xs px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-mono">
              All 4 Modules Active
            </span>
          </div>

          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div class="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800">
              <div class="flex items-center justify-between text-xs font-semibold text-slate-200">
                <span>1. Volumetric DDoS (XDP)</span>
                <span class="text-emerald-400">Active</span>
              </div>
              <p class="text-xs text-slate-400 mt-1">
                Token-bucket rate limiter inspecting SYN/UDP floods with nanosecond bpf_ktime tracking.
              </p>
            </div>

            <div class="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800">
              <div class="flex items-center justify-between text-xs font-semibold text-slate-200">
                <span>2. DNS Tunneling Detector</span>
                <span class="text-emerald-400">Active</span>
              </div>
              <p class="text-xs text-slate-400 mt-1">
                Shannon entropy analysis and cryptomining pool domain blacklisting on port 53.
              </p>
            </div>

            <div class="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800">
              <div class="flex items-center justify-between text-xs font-semibold text-slate-200">
                <span>3. LSM Runtime Integrity</span>
                <span class="text-emerald-400">Enforced</span>
              </div>
              <p class="text-xs text-slate-400 mt-1">
                BLAKE3 binary hash verification, namespace escape heuristics, ephemeral execution denial.
              </p>
            </div>

            <div class="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800">
              <div class="flex items-center justify-between text-xs font-semibold text-slate-200">
                <span>4. Reconnaissance & Port Scan</span>
                <span class="text-emerald-400">Active</span>
              </div>
              <p class="text-xs text-slate-400 mt-1">
                Sliding-window SYN/FIN port scanning heuristics flagging lateral probe attempts.
              </p>
            </div>
          </div>
        </div>
      </div>

      <!-- CRD Policies Table -->
      <div class="glass-panel rounded-2xl overflow-hidden border border-slate-800">
        <div class="p-4 bg-slate-900/60 border-b border-slate-800 flex items-center justify-between">
          <h2 class="text-sm font-semibold text-white">Active Kubernetes Security Policies (CRDs)</h2>
          <span class="text-xs font-mono text-slate-400">{{ data.policies().length }} CRDs Compiled</span>
        </div>

        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs font-mono">
            <thead class="bg-slate-900/90 text-slate-400 border-b border-slate-800">
              <tr>
                <th class="py-3 px-4">CRD RESOURCE NAME</th>
                <th class="py-3 px-4">KIND</th>
                <th class="py-3 px-4">NAMESPACE</th>
                <th class="py-3 px-4">SELECTOR TARGET</th>
                <th class="py-3 px-4">ENFORCED ACTION</th>
                <th class="py-3 px-4">STATUS</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800/60">
              @for (policy of data.policies(); track policy.name) {
                <tr class="hover:bg-slate-900/40 transition">
                  <td class="py-3 px-4 text-white font-medium">
                    {{ policy.name }}
                  </td>
                  <td class="py-3 px-4 text-cyan-400">
                    {{ policy.kind }}
                  </td>
                  <td class="py-3 px-4 text-slate-400">
                    {{ policy.namespace }}
                  </td>
                  <td class="py-3 px-4 text-slate-300">
                    {{ policy.selector }}
                  </td>
                  <td class="py-3 px-4 text-slate-200 font-sans">
                    {{ policy.action }}
                  </td>
                  <td class="py-3 px-4">
                    <span class="px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-800 font-semibold text-[10px]">
                      {{ policy.status }}
                    </span>
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
export class SecurityComponent {
  readonly data = inject(KwallDataService);

  newBlacklistIp = '';

  addIp(): void {
    const ip = this.newBlacklistIp.trim();
    if (ip) {
      this.data.addBlacklistIp(ip);
      this.newBlacklistIp = '';
    }
  }
}
