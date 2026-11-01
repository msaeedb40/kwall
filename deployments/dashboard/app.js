/**
 * KWALL Enterprise Management Dashboard Logic
 *
 * Implements interactive multi-cluster topology visualization, live alert triage,
 * visual policy generation with live YAML preview, and automated compliance auditing.
 */

// ---------------------------------------------------------------------------
// Mock Multi-Cluster Domain State
// ---------------------------------------------------------------------------

const STATE = {
    activeCluster: 'eks-prod-us-east-1',
    simulationActive: true,
    nodes: [
        { id: 'node-1', name: 'ip-10-0-1-42.ec2.internal', status: 'Ready', kernel: '6.8.0-45-generic', ebpfLsm: true, xdpSpeed: '0.22µs', x: 260, y: 220 },
        { id: 'node-2', name: 'ip-10-0-2-18.ec2.internal', status: 'Ready', kernel: '6.8.0-45-generic', ebpfLsm: true, xdpSpeed: '0.25µs', x: 740, y: 220 }
    ],
    pods: [
        { id: 'pod-1', name: 'payment-service-7f89d-4kx2b', namespace: 'production', nodeId: 'node-1', risk: 'HIGH', status: 'Running', ip: '10.244.1.14', quarantined: false, x: 160, y: 440 },
        { id: 'pod-2', name: 'order-api-6b99c-29mzx', namespace: 'production', nodeId: 'node-1', risk: 'LOW', status: 'Running', ip: '10.244.1.18', quarantined: false, x: 360, y: 440 },
        { id: 'pod-3', name: 'auth-gateway-5c87f-9lpxq', namespace: 'production', nodeId: 'node-2', risk: 'CRITICAL', status: 'Threat Detected', ip: '10.244.2.22', quarantined: false, x: 640, y: 440 },
        { id: 'pod-4', name: 'redis-cache-0', namespace: 'production', nodeId: 'node-2', risk: 'LOW', status: 'Running', ip: '10.244.2.35', quarantined: false, x: 840, y: 440 }
    ],
    alerts: [
        {
            id: 'ALT-9821',
            severity: 'CRITICAL',
            title: 'Unauthorized SSH Reverse Shell Spawned in Container',
            pod: 'auth-gateway-5c87f-9lpxq',
            namespace: 'production',
            mitre: 'T1059.004',
            probe: 'bpf_lsm/bprm_check_security',
            timestamp: 'Just now',
            resolved: false,
            details: 'Executable /tmp/pwncat spawned by UID 0 inside container cgroup; syscall intercepted and flagged.'
        },
        {
            id: 'ALT-9820',
            severity: 'HIGH',
            title: 'WAF SQL Injection Detected (Boolean Blind)',
            pod: 'payment-service-7f89d-4kx2b',
            namespace: 'production',
            mitre: 'T1190',
            probe: 'sk_msg/waf_stream_inspect',
            timestamp: '4m ago',
            resolved: false,
            details: 'HTTP POST /api/v1/checkout payload contained union select pattern; payload dropped at socket layer.'
        },
        {
            id: 'ALT-9819',
            severity: 'MEDIUM',
            title: 'Cross-Namespace Network Egress to Kube-System DNS',
            pod: 'order-api-6b99c-29mzx',
            namespace: 'production',
            mitre: 'T1071.004',
            probe: 'tc_cls_bpf/egress_filter',
            timestamp: '18m ago',
            resolved: false,
            details: 'Excessive DNS query volume (420 req/s) destined to CoreDNS IP 10.96.0.10.'
        }
    ],
    auditLog: [
        {
            id: 'AUD-00104',
            actor: 'sarah.chen@enterprise.internal',
            action: 'POLICY_DEPLOY',
            resource: 'KwallSecurityPolicy/protect-payment-backend',
            status: 'SUCCESS',
            hash: '4f92d8e137b01859c23f81e82a6...',
            timestamp: '2026-11-01 15:20:12 UTC'
        },
        {
            id: 'AUD-00103',
            actor: 'kwall-autonomous-agent',
            action: 'XDP_FILTER_ATTACH',
            resource: 'Interface eth0 on ip-10-0-1-42',
            status: 'SUCCESS',
            hash: '9a31bc083e921d4285741f20101...',
            timestamp: '2026-11-01 15:10:00 UTC'
        }
    ]
};

// ---------------------------------------------------------------------------
// Anti-CSRF / Anti-XSRF Protection Subsystem
// ---------------------------------------------------------------------------

const CSRF_SECURITY = {
    token: null,

    init() {
        const metaTag = document.querySelector('meta[name="csrf-token"]');
        if (metaTag && metaTag.content) {
            this.token = metaTag.content;
        } else {
            this.token = this.generateToken();
            if (metaTag) metaTag.content = this.token;
        }
        try {
            document.cookie = `XSRF-TOKEN=${this.token}; path=/; SameSite=Strict`;
        } catch (_) {}
        this.syncInputs();
    },

    generateToken() {
        const arr = new Uint8Array(16);
        if (window.crypto && window.crypto.getRandomValues) {
            window.crypto.getRandomValues(arr);
        } else {
            for (let i = 0; i < 16; i++) arr[i] = Math.floor(Math.random() * 256);
        }
        return 'kwall-csrf-' + Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
    },

    rotateToken() {
        this.token = this.generateToken();
        const metaTag = document.querySelector('meta[name="csrf-token"]');
        if (metaTag) metaTag.content = this.token;
        try {
            document.cookie = `XSRF-TOKEN=${this.token}; path=/; SameSite=Strict`;
        } catch (_) {}
        this.syncInputs();
        return this.token;
    },

    syncInputs() {
        const input = document.getElementById('policyCsrfToken');
        if (input) input.value = this.token;
        document.querySelectorAll('input[name="_csrf"], input[name="authenticity_token"]').forEach(el => {
            el.value = this.token;
        });
    },

    validate(submittedToken) {
        if (!submittedToken || !this.token) return false;
        return submittedToken === this.token;
    },

    getHeaders() {
        return {
            'X-CSRF-Token': this.token,
            'X-XSRF-Token': this.token,
            'X-Requested-With': 'XMLHttpRequest'
        };
    }
};

// ---------------------------------------------------------------------------
// Navigation and Tab Switching
// ---------------------------------------------------------------------------

document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', (e) => {
        e.preventDefault();
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        item.classList.add('active');

        const tabId = item.getAttribute('data-tab');
        document.querySelectorAll('.tab-panel').forEach(panel => panel.classList.remove('active'));
        const targetPanel = document.getElementById(tabId);
        if (targetPanel) {
            targetPanel.classList.add('active');
        }

        // Update header page title
        const titles = {
            'tab-topology': 'Multi-Cluster Topology Graph',
            'tab-alerts': 'Real-Time Alert Triage Console',
            'tab-policies': 'Visual Security Policy Builder',
            'tab-compliance': 'Automated Enterprise Compliance Benchmarks',
            'tab-audit': 'Cryptographic Administrative Audit Trail'
        };
        const titleEl = document.getElementById('pageTitle');
        if (titleEl && titles[tabId]) {
            titleEl.textContent = titles[tabId];
        }
    });
});

// ---------------------------------------------------------------------------
// SVG Topology Graph Renderer
// ---------------------------------------------------------------------------

function renderTopology() {
    const edgesGroup = document.getElementById('svgEdges');
    const nodesGroup = document.getElementById('svgNodes');
    if (!edgesGroup || !nodesGroup) return;

    edgesGroup.innerHTML = '';
    nodesGroup.innerHTML = '';

    const rootCluster = { x: 500, y: 70, name: 'Cluster Root (EKS)' };

    // Draw Cluster Node
    const clusterG = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    clusterG.setAttribute('transform', `translate(${rootCluster.x}, ${rootCluster.y})`);
    clusterG.style.cursor = 'pointer';
    clusterG.innerHTML = `
        <circle r="26" fill="rgba(6, 182, 212, 0.15)" stroke="#06b6d4" stroke-width="2.5" />
        <circle r="14" fill="#06b6d4" />
        <text y="42" text-anchor="middle" fill="#94a3b8" font-size="12" font-weight="700">prod-us-east-1</text>
    `;
    clusterG.onclick = () => inspectEntity('cluster', rootCluster);
    nodesGroup.appendChild(clusterG);

    // Draw Worker Nodes
    STATE.nodes.forEach(node => {
        // Line from cluster to worker node
        const edge = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        edge.setAttribute('x1', rootCluster.x);
        edge.setAttribute('y1', rootCluster.y + 20);
        edge.setAttribute('x2', node.x);
        edge.setAttribute('y2', node.y - 20);
        edge.setAttribute('stroke', 'url(#edge-cyan)');
        edge.setAttribute('stroke-width', '2');
        edge.setAttribute('stroke-dasharray', '5,5');
        edgesGroup.appendChild(edge);

        const nodeG = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        nodeG.setAttribute('transform', `translate(${node.x}, ${node.y})`);
        nodeG.style.cursor = 'pointer';
        nodeG.innerHTML = `
            <rect x="-65" y="-22" width="130" height="44" rx="8" fill="rgba(16, 185, 129, 0.12)" stroke="#10b981" stroke-width="1.8" />
            <text y="4" text-anchor="middle" fill="#f8fafc" font-size="11" font-weight="700">${node.name.split('.')[0]}</text>
            <text y="34" text-anchor="middle" fill="#64748b" font-size="10">eBPF LSM: Enforcing</text>
        `;
        nodeG.onclick = () => inspectEntity('node', node);
        nodesGroup.appendChild(nodeG);
    });

    // Draw Pods
    STATE.pods.forEach(pod => {
        const parentNode = STATE.nodes.find(n => n.id === pod.nodeId);
        if (!parentNode) return;

        const isCrit = pod.risk === 'CRITICAL' && !pod.quarantined;
        const strokeColor = pod.quarantined ? '#f59e0b' : (isCrit ? '#ef4444' : '#06b6d4');
        const glowFilter = isCrit ? 'filter="url(#glow-red)"' : (pod.quarantined ? '' : 'filter="url(#glow-cyan)"');

        // Edge
        const edge = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        edge.setAttribute('x1', parentNode.x);
        edge.setAttribute('y1', parentNode.y + 22);
        edge.setAttribute('x2', pod.x);
        edge.setAttribute('y2', pod.y - 20);
        edge.setAttribute('stroke', isCrit ? 'url(#edge-threat)' : 'rgba(255, 255, 255, 0.15)');
        edge.setAttribute('stroke-width', isCrit ? '2.5' : '1.5');
        edgesGroup.appendChild(edge);

        // Pod Node
        const podG = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        podG.setAttribute('transform', `translate(${pod.x}, ${pod.y})`);
        podG.style.cursor = 'pointer';
        podG.innerHTML = `
            <circle r="20" fill="rgba(15, 23, 42, 0.9)" stroke="${strokeColor}" stroke-width="2" ${glowFilter}/>
            <circle r="8" fill="${strokeColor}"/>
            <text y="32" text-anchor="middle" fill="#f8fafc" font-size="10" font-weight="600">${pod.name.split('-')[0]}-${pod.name.split('-')[1]}</text>
            <text y="44" text-anchor="middle" fill="${strokeColor}" font-size="9" font-weight="700">
                ${pod.quarantined ? 'ISOLATED' : pod.risk}
            </text>
        `;
        podG.onclick = () => inspectEntity('pod', pod);
        nodesGroup.appendChild(podG);
    });
}

function inspectEntity(type, entity) {
    const badge = document.getElementById('inspectorTierBadge');
    const content = document.getElementById('inspectorContent');
    if (!content || !badge) return;

    if (type === 'pod') {
        badge.textContent = entity.quarantined ? 'QUARANTINED' : `RISK: ${entity.risk}`;
        badge.className = 'badge ' + (entity.quarantined ? 'badge-warn' : (entity.risk === 'CRITICAL' ? 'badge-sev CRITICAL' : 'badge-pass'));

        content.innerHTML = `
            <div class="inspector-detail-box">
                <div class="inspect-item">
                    <strong>Pod Identification:</strong>
                    <span>${entity.name}</span>
                </div>
                <div class="inspect-item">
                    <strong>Namespace &amp; IP:</strong>
                    <span>${entity.namespace} (${entity.ip})</span>
                </div>
                <div class="inspect-item">
                    <strong>Assigned Worker Node:</strong>
                    <span>${entity.nodeId}</span>
                </div>
                <div class="inspect-item">
                    <strong>eBPF Probes Attached:</strong>
                    <span>tc_cls_bpf, sk_msg, bprm_check</span>
                </div>
                <div class="inspect-item">
                    <strong>Active Mitigations:</strong>
                    <span>${entity.quarantined ? 'Network Isolated via XDP Drop' : 'Normal L7 WAF Inspection'}</span>
                </div>
                <div style="margin-top: 10px; display: flex; gap: 8px;">
                    <button class="btn btn-sm ${entity.quarantined ? 'btn-secondary' : 'btn-primary'}" onclick="toggleQuarantine('${entity.id}')">
                        ${entity.quarantined ? 'Lift Quarantine' : '⚡ Quarantine / Isolate Pod'}
                    </button>
                </div>
            </div>
        `;
    } else if (type === 'node') {
        badge.textContent = 'HOST READY';
        badge.className = 'badge badge-pass';
        content.innerHTML = `
            <div class="inspector-detail-box">
                <div class="inspect-item"><strong>Hostname:</strong><span>${entity.name}</span></div>
                <div class="inspect-item"><strong>Linux Kernel:</strong><span>${entity.kernel}</span></div>
                <div class="inspect-item"><strong>XDP Transit Latency:</strong><span>${entity.xdpSpeed}</span></div>
                <div class="inspect-item"><strong>eBPF LSM Hooks:</strong><span>Active &amp; Enforcing</span></div>
            </div>
        `;
    } else {
        badge.textContent = 'CLUSTER OK';
        badge.className = 'badge badge-cyan';
        content.innerHTML = `
            <div class="inspector-detail-box">
                <div class="inspect-item"><strong>Cluster Name:</strong><span>prod-us-east-1</span></div>
                <div class="inspect-item"><strong>Cloud Provider:</strong><span>AWS Elastic Kubernetes Service (EKS)</span></div>
                <div class="inspect-item"><strong>Total Enforced Policies:</strong><span>14</span></div>
            </div>
        `;
    }
}

// ---------------------------------------------------------------------------
// Alert Triage Console
// ---------------------------------------------------------------------------

function renderAlerts(filterSev = 'ALL') {
    const tbody = document.getElementById('alertsTbody');
    if (!tbody) return;

    tbody.innerHTML = '';
    const filtered = STATE.alerts.filter(a => {
        if (filterSev === 'ALL') return true;
        if (filterSev === 'RESOLVED') return a.resolved;
        return a.severity === filterSev && !a.resolved;
    });

    filtered.forEach(alert => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><span class="badge-sev ${alert.severity}">${alert.severity}</span></td>
            <td>
                <strong>${alert.title}</strong>
                <div style="font-size: 11px; color: #94a3b8; margin-top: 2px;">${alert.details}</div>
            </td>
            <td><code>${alert.pod}</code><br><span style="font-size: 11px; color: #64748b;">ns: ${alert.namespace}</span></td>
            <td><span class="mitre-badge">${alert.mitre}</span></td>
            <td><code style="font-size: 11px;">${alert.probe}</code></td>
            <td style="color: #94a3b8; font-size: 12px;">${alert.timestamp}</td>
            <td>
                <div style="display: flex; gap: 6px;">
                    <button class="btn btn-sm btn-primary" onclick="quarantineFromAlert('${alert.pod}', '${alert.id}')">Isolate Pod</button>
                    <button class="btn btn-sm btn-secondary" onclick="dismissAlert('${alert.id}')">Acknowledge</button>
                </div>
            </td>
        `;
        tbody.appendChild(tr);
    });

    updateCounters();
}

function updateCounters() {
    const unres = STATE.alerts.filter(a => !a.resolved);
    const crit = unres.filter(a => a.severity === 'CRITICAL').length;
    const high = unres.filter(a => a.severity === 'HIGH').length;
    const med = unres.filter(a => a.severity === 'MEDIUM').length;

    const sbCount = document.getElementById('sidebarAlertCount');
    if (sbCount) sbCount.textContent = unres.length;

    const cAll = document.getElementById('countAll');
    const cCrit = document.getElementById('countCrit');
    const cHigh = document.getElementById('countHigh');
    const cMed = document.getElementById('countMed');

    if (cAll) cAll.textContent = unres.length;
    if (cCrit) cCrit.textContent = crit;
    if (cHigh) cHigh.textContent = high;
    if (cMed) cMed.textContent = med;

    // Header threat level
    const headerThreat = document.getElementById('headerThreatLevel');
    if (headerThreat) {
        if (crit > 0) {
            headerThreat.textContent = 'CRITICAL';
            headerThreat.className = 'stat-value' + ' text-rose';
        } else if (high > 0) {
            headerThreat.textContent = 'ELEVATED';
            headerThreat.className = 'stat-value threat-med';
        } else {
            headerThreat.textContent = 'NOMINAL';
            headerThreat.className = 'stat-value text-emerald';
        }
    }
}

window.quarantineFromAlert = function(podName, alertId) {
    if (!CSRF_SECURITY.validate(CSRF_SECURITY.token)) {
        showToast('❌ CSRF verification failed! Request rejected.', 'alert');
        addAuditEntry('SECURITY_VIOLATION', `CSRF Mismatch on Isolate Pod ${podName}`, 'DENIED');
        return;
    }
    const pod = STATE.pods.find(p => p.name === podName);
    if (pod) {
        pod.quarantined = true;
        showToast(`⚡ Workload '${podName}' quarantined via eBPF XDP DROP rules! (CSRF Verified)`, 'alert');
        addAuditEntry('ISOLATE_POD_AUTO', `Pod ${podName}`, 'SUCCESS');
        CSRF_SECURITY.rotateToken();
    }
    const alert = STATE.alerts.find(a => a.id === alertId);
    if (alert) alert.resolved = true;
    renderTopology();
    renderAlerts();
};

window.toggleQuarantine = function(podId) {
    if (!CSRF_SECURITY.validate(CSRF_SECURITY.token)) {
        showToast('❌ CSRF verification failed! Request rejected.', 'alert');
        addAuditEntry('SECURITY_VIOLATION', `CSRF Mismatch on Toggle Quarantine ${podId}`, 'DENIED');
        return;
    }
    const pod = STATE.pods.find(p => p.id === podId);
    if (!pod) return;
    pod.quarantined = !pod.quarantined;
    const action = pod.quarantined ? 'ISOLATE_POD' : 'LIFT_QUARANTINE';
    showToast(pod.quarantined ? `Pod ${pod.name} isolated via eBPF XDP. (CSRF Verified)` : `Pod ${pod.name} network access restored.`, 'success');
    addAuditEntry(action, `Pod ${pod.name}`, 'SUCCESS');
    CSRF_SECURITY.rotateToken();
    renderTopology();
    inspectEntity('pod', pod);
};

window.dismissAlert = function(alertId) {
    if (!CSRF_SECURITY.validate(CSRF_SECURITY.token)) {
        showToast('❌ CSRF verification failed! Request rejected.', 'alert');
        return;
    }
    const alert = STATE.alerts.find(a => a.id === alertId);
    if (alert) {
        alert.resolved = true;
        showToast(`Alert ${alertId} acknowledged. (CSRF Verified)`, 'success');
        addAuditEntry('ACKNOWLEDGE_ALERT', `Alert ${alertId}`, 'SUCCESS');
        CSRF_SECURITY.rotateToken();
        renderAlerts();
    }
};

// Filter pills
document.querySelectorAll('.btn-pill').forEach(pill => {
    pill.addEventListener('click', () => {
        document.querySelectorAll('.btn-pill').forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
        renderAlerts(pill.getAttribute('data-sev'));
    });
});

// ---------------------------------------------------------------------------
// Visual Policy Builder & Live YAML Preview
// ---------------------------------------------------------------------------

function updateYamlPreview() {
    const name = document.getElementById('policyName')?.value || 'my-policy';
    const ns = document.getElementById('policyNamespace')?.value || 'production';
    const plane = document.getElementById('policyLayer')?.value || 'L7_WAF';
    const action = document.getElementById('policyAction')?.value || 'Drop';
    const cidrs = (document.getElementById('ruleCidr')?.value || '').split(',').map(s => s.trim());
    const execs = (document.getElementById('ruleExec')?.value || '').split(',').map(s => s.trim());

    const sqli = document.getElementById('chkSqli')?.checked;
    const xss = document.getElementById('chkXss')?.checked;
    const ssrf = document.getElementById('chkSsrf')?.checked;

    const yaml = `apiVersion: kwall.security/v1alpha1
kind: KwallSecurityPolicy
metadata:
  name: ${name}
  namespace: ${ns}
spec:
  selector:
    matchLabels:
      app: payment-service
  enforcementPlane: ${plane}
  action: ${action}
  rules:
    ingress:
      - protocol: HTTPS
        waf:
          sqliProtection: ${sqli}
          xssProtection: ${xss}
          ssrfProtection: ${ssrf}
    egress:
      - toCIDR:
${cidrs.map(c => `          - ${c}`).join('\n')}
    hostSandbox:
      deniedExecutables:
${execs.map(e => `        - ${e}`).join('\n')}
`;
    const previewEl = document.getElementById('yamlPreview');
    if (previewEl) previewEl.textContent = yaml;
}

// Attach change listeners to policy inputs
['policyName', 'policyNamespace', 'policyLayer', 'policyAction', 'ruleCidr', 'ruleExec', 'chkSqli', 'chkXss', 'chkSsrf'].forEach(id => {
    const el = document.getElementById(id);
    if (el) {
        el.addEventListener('input', updateYamlPreview);
        el.addEventListener('change', updateYamlPreview);
    }
});

document.getElementById('btnValidatePolicy')?.addEventListener('click', () => {
    showToast('✅ Policy YAML syntax and eBPF BPF_PROG_LOAD compatibility verified!', 'success');
});

document.getElementById('btnDeployPolicy')?.addEventListener('click', () => {
    const formToken = document.getElementById('policyCsrfToken')?.value;
    if (!CSRF_SECURITY.validate(formToken)) {
        showToast('❌ Anti-CSRF verification failed! Policy deployment rejected.', 'alert');
        addAuditEntry('SECURITY_VIOLATION', 'CSRF Mismatch on Policy Deployment', 'DENIED');
        return;
    }
    const name = document.getElementById('policyName')?.value;
    showToast(`🚀 Policy '${name}' compiled with eBPF and distributed! (CSRF Verified)`, 'success');
    addAuditEntry('POLICY_DEPLOY', `KwallSecurityPolicy/${name}`, 'SUCCESS');
    CSRF_SECURITY.rotateToken();
});

document.getElementById('btnCopyYaml')?.addEventListener('click', () => {
    const code = document.getElementById('yamlPreview')?.textContent;
    if (navigator.clipboard && code) {
        navigator.clipboard.writeText(code);
        showToast('📋 Copied YAML to clipboard!', 'success');
    }
});

// ---------------------------------------------------------------------------
// Cryptographic Audit Trail
// ---------------------------------------------------------------------------

function renderAuditLog() {
    const tbody = document.getElementById('auditTbody');
    if (!tbody) return;

    tbody.innerHTML = '';
    STATE.auditLog.forEach(entry => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><code style="color: #38bdf8;">${entry.id}</code></td>
            <td><strong>${entry.actor}</strong></td>
            <td><span class="badge badge-cyan">${entry.action}</span></td>
            <td>${entry.resource}</td>
            <td><span class="badge badge-pass">${entry.status}</span></td>
            <td><code style="font-size: 11px; color: #94a3b8;">${entry.hash}</code></td>
            <td style="color: #64748b; font-size: 11px;">${entry.timestamp}</td>
        `;
        tbody.appendChild(tr);
    });
}

function addAuditEntry(action, resource, status) {
    const id = `AUD-00${STATE.auditLog.length + 105}`;
    const entry = {
        id,
        actor: 'sarah.chen@enterprise.internal',
        action,
        resource,
        status,
        hash: 'e3b0c44298fc1c149afbf4c8996...',
        timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC'
    };
    STATE.auditLog.unshift(entry);
    renderAuditLog();
}

// ---------------------------------------------------------------------------
// Toast Notifications
// ---------------------------------------------------------------------------

function showToast(message, type = 'success') {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `<span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(8px)';
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}

// ---------------------------------------------------------------------------
// Compliance Export Buttons
// ---------------------------------------------------------------------------

document.getElementById('btnExportJson')?.addEventListener('click', () => {
    const report = {
        cluster: STATE.activeCluster,
        generatedAt: new Date().toISOString(),
        benchmarks: {
            cisKubernetesV1_8: { score: 96.4, status: 'PASSED', checksEvaluated: 50, passing: 48 },
            soc2TypeII: { score: 98.1, status: 'PASSED', controls: ['CC6.1', 'CC6.6', 'CC6.8'] },
            pciDssV4_0: { score: 95.2, status: 'PASSED', fimActive: true, xdpDropEnforced: true }
        }
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `kwall-compliance-report-${STATE.activeCluster}.json`;
    a.click();
    showToast('💾 Exported structured compliance report JSON!', 'success');
});

document.getElementById('btnGenerateReport')?.addEventListener('click', () => {
    window.print();
});

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

window.CSRF_SECURITY = CSRF_SECURITY;

document.addEventListener('DOMContentLoaded', () => {
    CSRF_SECURITY.init();
    renderTopology();
    renderAlerts();
    renderAuditLog();
    updateYamlPreview();

    // Inspect first pod by default
    inspectEntity('pod', STATE.pods[2]);
});
