# KWALL CLI Reference Manual

`kwall` is the administrative command-line interface for inspecting and operating KWALL components on a node. It interacts with the local `kwall-agent` daemon through a dedicated Unix Domain Socket (`/var/run/kwall/kwall.sock`).

---

## Global Syntax

```bash
kwall [COMMAND] [SUBCOMMAND] [FLAGS]
```

### Global Options
- `-h, --help`: Print help information.
- `-V, --version`: Print KWALL CLI version and build metadata.

---

## Commands Overview

| Command | Subcommands | Description |
| :--- | :--- | :--- |
| **`status`** | — | Inspect overall node status, eBPF attachments, agent state, and uptime. |
| **`version`** | — | Show full version string, compiler toolchain, and git commit. |
| **`ebpf`** | `list`, `maps` | Inspect attached eBPF programs and view map statistics. |
| **`firewall`** | `status`, `stats` | View firewall state, packet counters, and drop metrics. |
| **`policy`** | `list`, `validate` | List active security policies or statically validate a policy YAML file. |
| **`network`** | `flows`, `interfaces` | Stream live kernel network flows or inspect managed netkit interfaces. |
| **`security`** | `alerts`, `stats` | Stream security alerts or view threat detection statistics. |

---

## Detailed Command Documentation

### 1. `kwall status`
Queries the agent via IPC and reports overall health, kernel compatibility, and subsystem status.

**Example Output:**
```
============================================================
KWALL Node Status
============================================================
Node Name:          worker-node-01
Kernel:             6.11.0-custom (BTF: OK, Netkit: OK, LSM: OK)
Agent PID:          14892
Uptime:             4d 12h 32m
Active Netkit Devs: 48
Loaded eBPF Progs:  96
Active Policies:    12
Total Packets Proc: 148,291,048
Dropped Packets:    42,109
Status:             HEALTHY
```

---

### 2. `kwall ebpf`

#### `kwall ebpf list`
Lists all eBPF programs currently loaded into the kernel by KWALL.
```bash
kwall ebpf list
```
**Output Columns**: `ID`, `Type`, `Name`, `Attached Device`, `Loaded At`, `Instructions`.

#### `kwall ebpf maps`
Displays all pinned and active BPF maps managed by KWALL.
```bash
kwall ebpf maps
```
**Output Columns**: `Map ID`, `Name`, `Type`, `Max Entries`, `Current Entries`, `Memory (KB)`.

---

### 3. `kwall firewall`

#### `kwall firewall status`
Shows whether firewall enforcement is active, permissive, or in audit mode.
```bash
kwall firewall status
```

#### `kwall firewall stats`
Displays total accepted packets, dropped packets, policy rejections, and rate-limited flows.
```bash
kwall firewall stats
```

---

### 4. `kwall policy`

#### `kwall policy list`
Lists all active network and security policies enforced on this node.
```bash
kwall policy list
```

#### `kwall policy validate`
Validates a local YAML policy manifest without applying it to the cluster.
```bash
kwall policy validate --file /path/to/policy.yaml
```

---

### 5. `kwall network`

#### `kwall network flows`
Streams live network flows captured directly from the eBPF TC ring buffer.
```bash
kwall network flows
```
**Output Stream Format:**
```
[12:04:19.492] ALLOW TCP 10.244.1.14:48292 -> 10.244.2.8:8080 (src_id=102, dst_id=204, len=64)
[12:04:19.493] DROP  TCP 10.244.1.14:48294 -> 10.244.3.5:22   (src_id=102, dst_id=999, reason=POLICY_DENY)
```

#### `kwall network interfaces`
Lists all network interfaces currently under KWALL management (physical and netkit devices).
```bash
kwall network interfaces
```

---

### 6. `kwall security`

#### `kwall security alerts`
Streams real-time threat detection alerts and policy violation events.
```bash
kwall security alerts
```

#### `kwall security stats`
Displays aggregate statistics on blocked DDoS attacks, port scan detections, and unauthorized exec attempts.
```bash
kwall security stats
```
