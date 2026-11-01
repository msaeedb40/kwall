# KWALL API Reference

The KWALL platform provides three interface planes:
1. **GraphQL Gateway** (`/graphql`): Hierarchical multi-cluster querying.
2. **REST API (OpenAPI v3)** (`/api/v1/`): Standard JSON endpoints for SIEM/SOAR.
3. **gRPC Control Plane** (`:50051`): High-throughput agent-to-server event streaming.

---

## 1. GraphQL API Gateway (`/graphql`)

### Sample Query: Cluster Topology, Pod Risk & Active Alerts
```graphql
query GetClusterSecurityPosture {
  clusters {
    id
    name
    provider
    status
    nodes {
      id
      hostname
      ebpfReady
      lsmSupported
      workloads {
        podName
        namespace
        riskScore
        riskTier
        alerts {
          id
          severity
          category
          mitreTactic
          description
        }
        networkFlows {
          srcIp
          dstIp
          bytes
          action
        }
      }
    }
    policies {
      id
      name
      enforcementPlane
      action
      status
    }
  }
}
```

### Filtering Alerts
```graphql
query FilterCriticalThreats {
  alerts(filter: { severity: CRITICAL, resolved: false }) {
    id
    severity
    title
    namespace
    podName
    mitreTactic
    timestamp
  }
}
```

---

## 2. REST API (OpenAPI v3) Surface

All REST endpoints require an `Authorization: Bearer <token>` header or OIDC session.

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/clusters` | List all federated Kubernetes clusters and their eBPF health. |
| `GET` | `/api/v1/clusters/{id}/nodes` | Inspect worker nodes, kernel versions, and probe statuses. |
| `GET` | `/api/v1/alerts` | Query active security violations (`?severity=CRITICAL&resolved=false`). |
| `POST` | `/api/v1/alerts/{id}/resolve` | Acknowledge or dismiss an alert with reason. |
| `POST` | `/api/v1/pod/quarantine` | Dynamically apply XDP drop rules to isolate a compromised pod. |
| `GET` | `/api/v1/policies` | Retrieve all active `KwallSecurityPolicy` definitions. |
| `POST` | `/api/v1/policies/validate` | Validate policy YAML against kernel verifier constraints. |
| `GET` | `/api/v1/compliance/{framework}` | Generate compliance reports for `cis`, `soc2`, or `pci-dss`. |
| `GET` | `/api/v1/audit/log` | Export cryptographic SHA-256 hash-chained audit ledger. |
| `GET` | `/api/v1/audit/verify` | Verify cryptographic integrity of the entire audit chain. |

---

## 3. Authentication & RBAC

### OIDC / Keycloak Integration
KWALL supports standard OpenID Connect JWT tokens issued by Keycloak, Okta, Dex, or Google Workspace:
* **Token Validation**: Issuer (`iss`), Audience (`aud`), and Expiration (`exp`) validated with clock skew tolerance.
* **Role Mapping**: Enterprise roles extracted directly from JWT claims:
  * `Admin`: Full permissions across all clusters and eBPF engine configurations.
  * `SecurityAnalyst`: Alert triage, forensics inspection, and one-click pod quarantine.
  * `PolicyEditor`: Create, validate, update, and delete security policy CRDs.
  * `Auditor`: Inspect compliance benchmarks, verify audit hash chains, and approve changes.
  * `Viewer`: Read-only access to topology and telemetry.

### Anti-CSRF / Anti-XSRF Headers
Mutating REST/GraphQL requests require:
* Header `X-CSRF-Token`: Current session authenticity token.
* Header `X-Requested-With`: `XMLHttpRequest`.
* Double-submit cookie `XSRF-TOKEN` with `SameSite=Strict`.
