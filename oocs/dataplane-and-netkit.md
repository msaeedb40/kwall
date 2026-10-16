# Dataplane & Netkit Integration

KWALL replaces legacy Linux `veth` pair networking with modern **netkit** virtual devices. Netkit (introduced in Linux 6.8) is purpose-built for eBPF-native container networking, delivering direct packet steering and eliminating unnecessary network stack overhead.

---

## Netkit vs Legacy Veth Architecture

### Traditional Veth Pairs
In traditional Kubernetes container networking:
- Packets traverse the host TCP/IP stack, enter a `veth` pair, traverse sk_buff allocation, socket queueing, and enter the container's network namespace through a virtual device.
- Involves multiple context switches, duplicate packet cloning, and high CPU usage under high traffic loads.

### Netkit in KWALL
```
Host Network Namespace                               Container Network Namespace
┌──────────────────────────────────────────────┐     ┌────────────────────────┐
│                                              │     │                        │
│   eBPF TC Ingress / Egress                   │     │   Application Socket   │
│   (kwall-ebpf classifier)                    │     │                        │
│             ▲                                │     │           ▲            │
│             │ Direct Memory Buffer Transfer   │     │           │            │
│             ▼                                │     │           ▼            │
│   netkit Primary (nkp-<id>) ──────────────────────────► netkit Peer (eth0)  │
│                                              │     │                        │
└──────────────────────────────────────────────┘     └────────────────────────┘
```

- **Direct Switching**: Packets move between the host netkit primary device and the container netns peer without intermediate bridge processing or socket queue delays.
- **Native eBPF Attachment**: BPF programs attached to netkit primary devices can return `NETKIT_PASS`, `NETKIT_REDIRECT`, or `NETKIT_DROP`.

---

## eBPF Program Attach Points

KWALL attaches eBPF programs at four strategic kernel locations:

```
                  Physical NIC (Incoming Packet)
                                │
                                ▼
                       ┌─────────────────┐
                       │   XDP Program   │ ◄── Volumetric DDoS Defense
                       └────────┬────────┘     (Early wire-speed drop)
                                │
                        Host IP Routing
                                │
                                ▼
                       ┌─────────────────┐
                       │ netkit Primary  │
                       │   TC Ingress    │ ◄── Policy Enforcement & Conntrack
                       └────────┬────────┘
                                │
                         Container eth0
                                │
                                ▼
                       ┌─────────────────┐
                       │  cgroup / Sock  │ ◄── Socket Acceleration
                       └────────┬────────┘
                                │
                           Container App
```

1. **XDP (eXpress Data Path)**:
   - Attached to the host's physical network interface (e.g. `eth0` or `bond0`).
   - Drops malformed packets, syn floods, and blocked CIDR ranges before memory (`sk_buff`) allocation occurs.
2. **Traffic Control (TC) Ingress (`tc_ingress`)**:
   - Attached to the `netkit` primary device on the host.
   - Evaluates incoming container packets against ingress policy tables and validates connection tracking state.
3. **Traffic Control (TC) Egress (`tc_egress`)**:
   - Attached to the `netkit` primary device on the host.
   - Evaluates outgoing container packets, stamps source security identities, and verifies egress policies.
4. **BPF Sockmap & Sockops**:
   - Attached to cgroups for local pod-to-pod communication.
   - Bypasses TCP/IP stack overhead for pods communicating on the same node by redirecting socket buffers directly between sender and receiver sockets.

---

## Packet Processing Lifecycle in KWALL

```
   Incoming Packet
         │
         ▼
   Parse Ethernet / IP / L4 Headers (Zero-Copy)
         │
         ▼
   Lookup Conntrack Table (CT)
   ├── Match Found (ESTABLISHED / RELATED) ──► Fast-Path Allow
   └── No Match (NEW Connection)
             │
             ▼
       Lookup Security Identity Table
       (Resolve src_ip -> src_identity, dst_ip -> dst_identity)
             │
             ▼
       Evaluate Policy LPM Trie
       ├── MATCH ALLOW ──► Insert CT Entry ──► NETKIT_PASS
       ├── MATCH DENY  ──► Emit Drop Event  ──► NETKIT_DROP
       └── DEFAULT     ──► Cluster Default Policy (Drop/Log)
```

### Connection Tracking (Conntrack) Table
- Maintained in `BPF_MAP_TYPE_LRU_HASH`.
- Tracks 5-tuple: `(src_ip, dst_ip, src_port, dst_port, protocol)`.
- Tracks TCP state transitions (`SYN_SENT`, `ESTABLISHED`, `FIN_WAIT`, `CLOSED`).
- Enables established return traffic without re-evaluating the full policy graph.
