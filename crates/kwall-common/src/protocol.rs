use kwall_ebpf_common::L4Protocol;

pub fn parse_l4_protocol(name: &str) -> L4Protocol {
    match name.to_uppercase().as_str() {
        "TCP" => L4Protocol::Tcp,
        "UDP" => L4Protocol::Udp,
        "ICMP" => L4Protocol::Icmp,
        "ICMPV6" => L4Protocol::Icmpv6,
        _ => L4Protocol::Unknown,
    }
}

pub fn protocol_to_str(proto: L4Protocol) -> &'static str {
    match proto {
        L4Protocol::Tcp => "TCP",
        L4Protocol::Udp => "UDP",
        L4Protocol::Icmp => "ICMP",
        L4Protocol::Icmpv6 => "ICMPv6",
        L4Protocol::Unknown => "UNKNOWN",
    }
}
