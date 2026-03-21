# SIGINT

**Silent Identity Guard via INput Telemetry**

A keystroke dynamics biometric dead man's switch for Linux. SIGINT passively builds a typing profile during an enrollment period, then continuously scores live typing sessions against that profile. When the operator's identity confidence drops below threshold — indicating someone else is at the keyboard — configurable responses fire: lock the screen or kill sessions.

It is not a login gate. It is a **session-continuous identity tripwire** that assumes the authenticated user may have been replaced mid-session.

## How It Works

```
evdev → [collector] → key class + timestamp → [analyzer] → score → [enforcer] → lock/kill
```

1. **Collector** reads raw keystroke events from `/dev/input/eventN`, pseudonymizes keycodes into 14 keyboard-region classes (no actual characters stored), and streams timestamped events to the analyzer.

2. **Analyzer** extracts biometric features (dwell time, flight time, digraph latency, burst cadence, error rate) and scores them against the enrolled profile using Scaled Mahalanobis Distance + per-digraph Z-score ensemble.

3. **Enforcer** applies policy thresholds and executes responses:

| Tier | Trigger | Action |
|------|---------|--------|
| AMBER | Score > τ for > grace period | Lock screen |
| RED | Score > τ_crit | Lock + kill sessions |

4. **sigint-ctl** provides administrative commands: enrollment, status, policy signing, key generation.

## Privacy

SIGINT never stores which key was pressed. The collector maps each physical key to a region class (`HOME_L`, `UPPER_R`, `SPACE`, etc.). An attacker who exfiltrates the profile sees timing patterns for digraphs like `HOME_L → UPPER_R` — not `f → u`. Profiles are encrypted at rest with AES-256-GCM.

## Building

Requires [Zig](https://ziglang.org/) 0.15+ on Linux.

```bash
zig build                          # Debug build, all 4 binaries
zig build -Doptimize=ReleaseSafe   # Production build
zig build test                     # Run all tests
zig build -Dwipe_support=true      # Enable BLACK response flag (wipe not yet implemented)
zig build -Dfeature_dim=90         # Use 90-dimensional feature vectors
```

Binaries are placed in `zig-out/bin/`:
- `sigint-collector`
- `sigint-analyzer`
- `sigint-enforcer`
- `sigint-ctl`

## Quick Start (Local Development)

Run all daemons with a local socket directory — no root required (except for the collector, which needs `/dev/input/` access):

```bash
# Terminal 1: enforcer
./zig-out/bin/sigint-enforcer --run-dir /tmp/sigint --policy doc/policy-example.toml --dry-run --skip-policy-sig

# Terminal 2: analyzer
./zig-out/bin/sigint-analyzer --run-dir /tmp/sigint --dry-run

# Terminal 3: collector (requires input group or sudo)
sudo ./zig-out/bin/sigint-collector --run-dir /tmp/sigint --dry-run

# Terminal 4: ctl
./zig-out/bin/sigint-ctl --run-dir /tmp/sigint status
./zig-out/bin/sigint-ctl --run-dir /tmp/sigint enroll start
```

## Installation (Production)

```bash
# Build
zig build -Doptimize=ReleaseSafe

# Install binaries, systemd units, and default config
sudo make install

# Create system users and set permissions
sudo make setup-users

# Generate policy signing keypair
sigint-ctl keygen --output /root/sigint-signing.key
# Store private key OFFLINE after signing

# Sign the policy
sigint-ctl policy sign --key /root/sigint-signing.key --policy /etc/sigint/policy.toml

# Enable and start services
sudo systemctl enable --now sigint-collector sigint-analyzer sigint-enforcer

# Begin enrollment (type normally for 7-30 days)
sigint-ctl enroll start

# Check enrollment quality
sigint-ctl enroll status

# Activate verification when ready
sigint-ctl enroll activate
```

## Policy Configuration

Policy is defined in TOML and must be signed with Ed25519:

```toml
[thresholds]
tau = 0.55          # AMBER trigger
tau_critical = 0.80 # RED trigger
grace_seconds = 45  # Seconds above tau before AMBER fires

[scoring]
alpha = 0.6         # Mahalanobis vs digraph ensemble weight
window_seconds = 30
min_events_per_window = 40

[adaptive]
micro_update_lambda = 0.005  # Profile drift rate
anchor_drift_max = 0.25      # Max drift from enrollment anchor
```

See [`doc/policy-example.toml`](doc/policy-example.toml) for the full configuration reference.

## Architecture

Four discrete processes communicating over Unix domain sockets with SO_PEERCRED authentication. No network sockets.

```
sigint-collector  →  sigint-analyzer  →  sigint-enforcer
       ↑                    ↑                    ↑
  CAP_DAC_READ_SEARCH  unprivileged        CAP_SYS_ADMIN
  (evdev access only)                      (loginctl)
```

Each process runs under a dedicated system user with:
- Minimal Linux capabilities (dropped after init)
- seccomp BPF syscall filters (comptime-generated allow-lists)
- Hardened systemd unit files (ProtectSystem=strict, PrivateNetwork=true, MemoryDenyWriteExecute=true)

## Scoring Model

**Primary: Scaled Mahalanobis Distance** against the enrolled mean/covariance, normalized via chi-squared CDF. Captures global typing rhythm deviations accounting for feature correlations.

**Secondary: Per-digraph Z-score ensemble.** Median |Z| across the top digraph classes. Catches adversaries who match global cadence but fail on specific key-pair timing.

**Combined:** `S = α · mahalanobis + (1-α) · digraph_ensemble` (default α = 0.6).

The profile adapts over time via exponential moving average micro-updates (λ = 0.005) on strong-match windows, with a frozen anchor profile that prevents adversarial drift.

## Design Document

The full threat model, architecture, and rationale are in [`DESIGN.md`](DESIGN.md).

## Dependencies

- Linux kernel (evdev subsystem)
- Zig 0.15+ standard library (crypto, networking, syscalls)
- No external dependencies. No libc.

## License

CC BY-SA 4.0
