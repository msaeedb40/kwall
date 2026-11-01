# KWALL Security Policy Specification (`KwallSecurityPolicy`)

KWALL exposes Kubernetes Custom Resource Definitions (CRDs) under API group `kwall.security/v1alpha1`. Policies configure multi-layer security enforcement directly compiled into eBPF maps.

---

## 1. Custom Resource Definition (CRD) Schema

```yaml
apiVersion: kwall.security/v1alpha1
kind: KwallSecurityPolicy
metadata:
  name: <string>
  namespace: <string>
spec:
  selector:
    matchLabels:
      <key>: <value>
  enforcementPlane: <L3_L4 | L7_WAF | LSM_SANDBOX | CRI_CONTAINER>
  action: <Allow | Drop | KillProcess | QuarantinePod | AuditOnly>
  rules:
    ingress:
      - protocol: <TCP | UDP | HTTP | HTTPS | GRPC>
        ports:
          - <integer>
        fromCIDR:
          - <cidr-string>
        waf:
          sqliProtection: <boolean>
          xssProtection: <boolean>
          ssrfProtection: <boolean>
          crlfProtection: <boolean>
    egress:
      - protocol: <TCP | UDP | HTTP | HTTPS | DNS>
        toCIDR:
          - <cidr-string>
        allowedDomains:
          - <domain-string>
    hostSandbox:
      deniedExecutables:
        - <path-string>
      readOnlyPaths:
        - <path-string>
      prohibitedCapabilities:
        - <linux-capability-string>
```

---

## 2. Practical Policy Examples

### Example 1: Multi-Layer Zero-Trust Payment Service Protection
Protects payment backend pods with L7 WAF, strict egress allowlists, and LSM binary execution restrictions:

```yaml
apiVersion: kwall.security/v1alpha1
kind: KwallSecurityPolicy
metadata:
  name: payment-defense-in-depth
  namespace: production
spec:
  selector:
    matchLabels:
      app: payment-service
      tier: backend
  enforcementPlane: L7_WAF
  action: Drop
  rules:
    ingress:
      - protocol: HTTPS
        ports:
          - 8443
        waf:
          sqliProtection: true
          xssProtection: true
          ssrfProtection: true
          crlfProtection: true
    egress:
      # Restrict egress strictly to database and payment gateway CIDRs
      - protocol: TCP
        toCIDR:
          - 10.244.1.0/24
          - 172.20.10.5/32
    hostSandbox:
      # Prevent interactive shells, network utils, and scripts from executing
      deniedExecutables:
        - /bin/sh
        - /bin/bash
        - /usr/bin/nc
        - /usr/bin/curl
        - /usr/bin/wget
        - /tmp/*
      readOnlyPaths:
        - /etc
        - /var/run/secrets/kubernetes.io
```

### Example 2: Ingress Nginx Anti-SSRF & Metadata Guard
Prevents server-side request forgery to cloud instance metadata (`169.254.169.254`):

```yaml
apiVersion: kwall.security/v1alpha1
kind: KwallSecurityPolicy
metadata:
  name: block-cloud-metadata-ssrf
  namespace: ingress-nginx
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: ingress-nginx
  enforcementPlane: L3_L4
  action: Drop
  rules:
    egress:
      - toCIDR:
          # Block AWS, GCP, and Azure IMDS
          - "!169.254.169.254/32"
```

### Example 3: Host Binary Sandbox & FIM Monitor
Locks down sensitive host paths and container rootfs:

```yaml
apiVersion: kwall.security/v1alpha1
kind: KwallSecurityPolicy
metadata:
  name: host-fim-and-privilege-guard
  namespace: kube-system
spec:
  selector:
    matchLabels:
      k8s-app: kube-dns
  enforcementPlane: LSM_SANDBOX
  action: KillProcess
  rules:
    hostSandbox:
      prohibitedCapabilities:
        - CAP_SYS_ADMIN
        - CAP_NET_RAW
        - CAP_BPF
      readOnlyPaths:
        - /etc/kubernetes
        - /var/lib/kubelet
        - /etc/resolv.conf
```
