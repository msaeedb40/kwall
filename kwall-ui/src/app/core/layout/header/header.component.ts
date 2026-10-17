import { Component, inject } from '@angular/core';
import { KwallDataService } from '../../services/kwall-data.service';
import { DecimalPipe } from '@angular/common';

@Component({
  selector: 'app-header',
  standalone: true,
  imports: [DecimalPipe],
  template: `
    <header class="h-16 border-b border-slate-800 bg-slate-950/80 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-40">
      <div class="flex items-center space-x-4">
        <div class="flex items-center space-x-2">
          <div class="w-8 h-8 rounded-lg bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center font-black text-white text-base shadow-lg shadow-cyan-500/20">
            KW
          </div>
          <span class="font-bold text-lg text-white tracking-wider">KWALL</span>
          <span class="text-xs px-2 py-0.5 rounded-full bg-cyan-950/80 text-cyan-400 border border-cyan-800 font-mono">
            Linux 6.8+ eBPF
          </span>
        </div>

        <div class="hidden md:flex items-center space-x-2 text-xs text-slate-400 pl-4 border-l border-slate-800">
          <span class="inline-block w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
          <span>Dataplane: <strong class="text-slate-200">netkit ACTIVE</strong></span>
          <span class="text-slate-600">|</span>
          <span>CO-RE: <strong class="text-emerald-400">BTF Loaded</strong></span>
        </div>
      </div>

      <div class="flex items-center space-x-6 text-sm">
        <div class="hidden lg:flex items-center space-x-5 text-xs font-mono">
          <div class="flex flex-col text-right">
            <span class="text-slate-500">PACKETS/S</span>
            <span class="text-cyan-400 font-bold">{{ data.metrics().packetsPerSec | number }}</span>
          </div>
          <div class="flex flex-col text-right">
            <span class="text-slate-500">P95 LATENCY</span>
            <span class="text-emerald-400 font-bold">{{ data.metrics().latencyP95Us }} µs</span>
          </div>
          <div class="flex flex-col text-right">
            <span class="text-slate-500">DROPS/S</span>
            <span class="text-rose-400 font-bold">{{ data.metrics().dropsPerSec }}</span>
          </div>
        </div>

        <div class="flex items-center space-x-3">
          <div class="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 flex items-center space-x-2 text-xs text-slate-300">
            <span class="w-2 h-2 rounded-full bg-cyan-400"></span>
            <span>Cluster: <span class="font-semibold text-white">production-k8s</span></span>
          </div>
        </div>
      </div>
    </header>
  `
})
export class HeaderComponent {
  readonly data = inject(KwallDataService);
}
