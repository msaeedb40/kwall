//! Fuzz harness for CIDR and network policy parser.

use kwall_policy::compiler::parse_cidr_string;

fn main() {
    // Deterministic fuzz corpus verification
    let corpus = [
        "10.0.0.0/8",
        "192.168.1.1/32",
        "0.0.0.0/0",
        "255.255.255.255/32",
        "999.999.999.999/999",
        "",
        "/",
        "///",
        "10.0.0.1/",
        "/32",
        "a.b.c.d/24",
        "10.0.0.1/-1",
        "127.0.0.1/33",
        "NaN/NaN",
        "10.0.0.1/10000000000000000000000000",
    ];

    for input in &corpus {
        let _ = parse_cidr_string(input);
    }

    println!("CIDR parser fuzzing passed across corpus without crashes or panics.");
}
