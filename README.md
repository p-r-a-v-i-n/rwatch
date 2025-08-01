# rwatch

Real-time Threat Detection using eBPF + Rust

rwatch is an eBPF-based threat detection tool written in Rust. It monitors Linux systems for suspicious or malicious behavior with minimal overhead.

## ✨ Why rwatch?
- Ultra-low overhead with eBPF
- Written in Rust for safety & performance
- Real-time event-driven architecture
- Easy to extend with custom detection rules

## ✅ Current Capabilities
- Captures execve events:
     - pid, uid, process name (comm)
     - filename, first 2 arguments (argv0, argv1)
     - Streams captured events via PerfEventArray to user space
     - CLI logging for basic visibility

## 🔜 Planned Features
- Detect suspicious behaviors like:
     - chmod +x on unknown files
     - Port scanning activity (burst of outbound connections)
     - Access to sensitive files (/etc/shadow, /root)
     - Creation of .enc files (possible ransomware indicator)
     - Fork bombs or rapid exec calls
- Rule-based detection engine (YAML/JSON rules)
- Event debouncing (to avoid log spam)
- Alerting via:
   - CLI
   - JSON log file
   - Optional Webhook integration


## Architecture
<img width="572" height="656" alt="rwatch-arch" src="https://github.com/user-attachments/assets/3be680df-ecf3-4a60-9778-6736d721a0e5" />


## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package rwatch --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/rwatch` can be
copied to a Linux server or VM and run there.

## License

With the exception of eBPF code, rwatch is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
