# rwatch

> Real-time threat detection for Linux using eBPF and Rust.

rwatch is an eBPF-based threat detection tool written in Rust. It monitors Linux systems for suspicious or malicious behavior with minimal overhead.

## ✨ Why rwatch?
- Ultra-low overhead with eBPF
- Written in Rust for safety & performance
- Real-time event-driven architecture
- Easy to extend with custom detection rules

## Features

| Capability | Hook | Description |
|------------|------|-------------|
| **Process Monitoring** | `sys_enter_execve` tracepoint | Captures all process executions with PID, UID, command, and filename |
| **Chmod Detection** | `__x64_sys_chmod` / `fchmodat` kprobe | Detects `chmod +x` on files outside trusted system paths |
| **Network Monitoring** | `tcp_connect` kprobe | Logs outbound TCP connections with destination IP, port, and process info |
| **File Integrity Monitoring** | `sys_enter_openat` tracepoint | Alerts on access to sensitive files (`/etc/shadow`, `/etc/passwd`, SSH keys) |

### Additional Capabilities

- **Dynamic Rule Engine** — Define detection rules in YAML without recompiling
- **SIEM-Ready Output** — Structured JSON output for integration with Splunk, ELK, Datadog, etc.
- **CLI Interface** — Configurable via command-line arguments
- **Systemd Support** — Production-ready service file included

## Architecture

<img width="572" height="656" alt="rwatch-arch" src="https://github.com/user-attachments/assets/3be680df-ecf3-4a60-9778-6736d721a0e5" />

## Quick Start

### Prerequisites

- Rust stable toolchain: `rustup toolchain install stable`
- Rust nightly toolchain: `rustup toolchain install nightly --component rust-src`
- bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

### Build

```shell
cargo build --release
```

### Run

```shell
# Text output (colored terminal)
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'

# With custom rules and JSON output
sudo ./target/release/rwatch --config rules.yaml --output json
```

### CLI Options

```
Usage: rwatch [OPTIONS]

Options:
  -c, --config <PATH>    Path to rules configuration file [default: rules.yaml]
  -o, --output <FORMAT>  Output format: text, json [default: text]
  -h, --help             Print help
  -V, --version          Print version
```

## Rules Configuration

Detection rules are defined in YAML. Example `rules.yaml`:

```yaml
rules:
  - rule_type:
      type: SuspiciousPathPrefix
      value: "/tmp"
    description: "Execution from /tmp is suspicious"
    severity: warning

  - rule_type:
      type: SuspiciousCommand
      value: "/usr/bin/nmap"
    description: "Port scanning tool detected"
    severity: critical
```

## Deployment

### Systemd Service

```shell
sudo cp target/release/rwatch /usr/local/bin/
sudo mkdir -p /etc/rwatch
sudo cp rwatch/rules.yaml /etc/rwatch/
sudo cp rwatch.service /etc/systemd/system/
sudo systemctl enable --now rwatch
```

### JSON Log Pipeline

```shell
# Pipe to jq for real-time analysis
sudo rwatch --output json | jq .

# Forward to a log file
sudo rwatch --output json >> /var/log/rwatch.json
```

## Cross-Compiling (macOS)

Cross compilation works on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package rwatch --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```

Additional macOS dependencies:
- LLVM: `brew install llvm`
- musl toolchain: `brew install filosottile/musl-cross/musl-cross`
- rustup target: `rustup target add ${ARCH}-unknown-linux-musl`

## Roadmap

- [ ] Event correlation and kill-chain detection
- [ ] Webhook / Slack alerting
- [ ] Log file rotation
- [ ] Container-aware detection (cgroup/namespace tracking)
- [ ] Event debouncing to reduce log noise
- [ ] DNS query monitoring

## License

With the exception of eBPF code, rwatch is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF Code

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
