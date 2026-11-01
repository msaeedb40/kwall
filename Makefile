.PHONY: all build build-ebpf check test clippy fmt clean

all: check test

build:
	cargo build --workspace

build-ebpf:
	cargo +nightly build --manifest-path ebpf/Cargo.toml --target bpfel-unknown-none -Z build-std=core --release

check:
	cargo check --workspace

test:
	cargo test --workspace

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

fmt:
	cargo fmt --all --check

fmt-fix:
	cargo fmt --all

clean:
	cargo clean
