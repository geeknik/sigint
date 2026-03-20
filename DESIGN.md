# SIGINT: Silent Identity Guard via INput Telemetry

## Dead Man's Switch via Keystroke Dynamics — Design Specification

**Classification:** Engineering Design Document
**Version:** 0.1.0-draft
**License:** CC BY-SA 4.0
**Status:** Pre-implementation

---

## 0. Thesis

Every human types like a fingerprint. Dwell times, flight times, digraph latency, error
correction cadence, modifier key habits — these are not conscious behaviors. They are
neuromuscular signatures. They cannot be convincingly faked at speed by an impersonator
who does not know they are being measured.

**SIGINT** is a daemon that:

1. Passively observes raw keystroke timing during an enrollment window (7–30 days).
2. Builds a per-user behavioral biometric model from that data.
3. Continuously scores live typing sessions against that model.
4. Executes configurable responses (lock, wipe, alert, dead-drop exfil) when the
   operator's identity confidence drops below threshold for a sustained period.

It is not a login gate. It is a **session-continuous identity tripwire** that assumes the
authenticated user may have been replaced mid-session.

---

## 1. Threat Model

### 1.1 Assumed Adversary

| Property            | Assumption                                                    |
|---------------------|---------------------------------------------------------------|
| Physical access     | Adversary has hands on keyboard post-authentication.          |
| Credential access   | Adversary may possess passwords, keys, or session tokens.     |
| Sophistication      | Competent operator, not a script kiddie.                      |
| Awareness           | Adversary does **not** know SIGINT is running.                |
| Time pressure       | Adversary has minutes to hours, not days.                     |
| Typing knowledge    | Adversary has **not** studied the owner's typing patterns.    |

### 1.2 Trust Boundaries

```
┌──────────────────────────────────────────────────────────┐
│                    KERNEL SPACE                          │
│  /dev/input/eventN  ←  evdev subsystem                  │
├──────────────────────────────────────────────────────────┤
│                    USER SPACE                            │
│                                                          │
│  ┌─────────────┐    ┌──────────────┐    ┌────────────┐  │
│  │  Collector   │───▶│  Analyzer    │───▶│  Enforcer  │  │
│  │  (captures   │    │  (scores     │    │  (locks/   │  │
│  │   raw evdev  │    │   sessions)  │    │   wipes/   │  │
│  │   events)    │    │              │    │   alerts)  │  │
│  └─────────────┘    └──────────────┘    └────────────┘  │
│         │                   │                   │        │
│         ▼                   ▼                   ▼        │
│  ┌─────────────┐    ┌──────────────┐    ┌────────────┐  │
│  │  Raw Event   │    │   Profile    │    │   Policy   │  │
│  │  Buffer      │    │   Store      │    │   Config   │  │
│  │  (tmpfs,     │    │   (encrypted │    │   (signed, │  │
│  │   volatile)  │    │    at rest)  │    │   static)  │  │
│  └─────────────┘    └──────────────┘    └────────────┘  │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

### 1.3 Assets Under Protection

| Asset                 | Sensitivity | Notes                                        |
|-----------------------|-------------|----------------------------------------------|
| Biometric profile     | CRITICAL    | Irrevocable if leaked. Cannot change typing.  |
| Policy configuration  | HIGH        | Reveals trigger thresholds and response type.  |
| Raw keystroke buffer   | HIGH        | Contains timing side-channel to typed content. |
| Enforcement credentials| CRITICAL   | LUKS keys, wipe authorization tokens.          |

### 1.4 What SIGINT Does NOT Defend Against

- Hardware keyloggers injecting synthetic events at wire level.
- Adversary who has studied the owner's typing via prior recording and replays synthetic
  input via a USB HID injection device at matching cadence.
- Kernel-level rootkits that intercept evdev before SIGINT's collector.
- Rubber-hose cryptanalysis (coerced typing by the legitimate user).

These are acknowledged, not ignored. Mitigations noted where partial coverage is possible.

---

## 2. Core Concepts

### 2.1 Keystroke Dynamics Features

Each keypress event yields a `(key, timestamp, direction)` tuple from evdev.
From sequential events, SIGINT extracts:

| Feature              | Definition                                         | Signal Value |
|----------------------|----------------------------------------------------|--------------|
| **Dwell time**       | Duration key is held (press → release)             | HIGH         |
| **Flight time**      | Interval between releasing key N and pressing N+1  | HIGH         |
| **Digraph latency**  | Press-to-press time for specific two-key sequences  | VERY HIGH    |
| **Trigraph latency** | Press-to-press across three-key sequences           | HIGH         |
| **Error rate**       | Frequency of backspace/delete sequences             | MEDIUM       |
| **Error correction pattern** | Timing shape of detect-backspace-retype     | HIGH         |
| **Modifier hold style** | How long Shift/Ctrl/Alt are held relative to the modified key | MEDIUM |
| **Pause distribution** | Statistical shape of inter-word and inter-phrase gaps | MEDIUM    |
| **Burst cadence**    | Typing speed within word bursts vs. between them    | HIGH         |
| **Key pressure**     | If available via supported hardware (rare on Linux) | LOW          |

### 2.2 Feature Stability Hierarchy

Not all features are equally stable across sessions. SIGINT weights features by
empirically observed intra-user consistency:

```
Tier 1 (Most Stable):  Digraph latencies for common pairs (th, he, in, er, an, re)
Tier 2:                 Dwell times for home-row keys, burst cadence
Tier 3:                 Flight times, trigraph latencies
Tier 4 (Least Stable): Pause distributions, error rates (mood/fatigue-dependent)
```

Tier 1 features dominate the scoring function. Tier 4 features are contextual modifiers,
never primary discriminators.

### 2.3 Enrollment vs. Verification

**Enrollment (days 1–N):**
- Passive collection only. No enforcement actions.
- Model is rebuilt incrementally as data accumulates.
- Minimum enrollment: 7 days of ≥ 30 minutes daily typing.
- Recommended enrollment: 14–30 days.
- Enrollment quality score exposed via status interface.
- User is warned if enrollment data is insufficient to produce a reliable model.

**Verification (day N+1 onward):**
- Continuous scoring against enrolled profile.
- Sliding window of last K seconds of typing (configurable, default 30s).
- Score is a normalized distance metric (0.0 = perfect match, 1.0 = total stranger).
- Enforcement triggers when score exceeds threshold for sustained duration.

---

## 3. Architecture

### 3.1 Component Model

SIGINT is four discrete processes communicating over Unix domain sockets with
authenticated (SO_PEERCRED) connections. No network sockets. No IPC over shared
filesystem paths writable by unprivileged users.

```
sigint-collector  →  sigint-analyzer  →  sigint-enforcer
       ↑                    ↑                    ↑
       │                    │                    │
  CAP_DAC_READ_SEARCH  unprivileged        CAP_SYS_BOOT (wipe)
  (evdev access only)                      CAP_SYS_ADMIN (lock)
                                           dropped after init
```

**sigint-collector:**
- Reads raw evdev events from /dev/input/eventN.
- Requires `input` group membership or `CAP_DAC_READ_SEARCH`.
- Strips key identity down to a pseudonymized key-class:
  - Home row left, home row right, upper row, lower row, modifier, punctuation, numpad.
  - SIGINT does **not** record which specific letter was pressed in its stored profile.
  - Timing features are computed against key-class digraphs, not literal character pairs.
  - This is a critical privacy decision. See §7.
- Emits `(key_class, timestamp_ns, press|release)` tuples to analyzer.

**sigint-analyzer:**
- Receives pseudonymized event stream.
- During enrollment: accumulates feature distributions, periodically rebuilds model.
- During verification: scores incoming windows against stored model.
- Emits `(timestamp, window_score, confidence)` to enforcer.
- Stateless between restarts except for the persisted profile store.

**sigint-enforcer:**
- Receives score stream.
- Applies policy rules (threshold, sustained duration, response type).
- Executes configured response.
- Has the only component with dangerous capabilities, acquired at init and dropped.
- Policy is loaded from a signed, read-only config file. Cannot be modified at runtime.

**sigint-ctl:**
- Administrative CLI for enrollment management, status queries, manual lock/unlock.
- Authenticates via Unix socket peercred (must be same UID or root).
- Cannot modify policy without re-signing the config.

### 3.2 Data Flow — Verification Mode

```
evdev event
  │
  ▼
[collector] ── key class + timestamp ──▶ [analyzer]
                                              │
                                    compute window features
                                              │
                                    score against profile
                                              │
                                    (score, confidence)
                                              │
                                              ▼
                                        [enforcer]
                                              │
                              ┌───────────────┼───────────────┐
                              ▼               ▼               ▼
                         score < τ      τ ≤ score < τ_crit   score ≥ τ_crit
                         (normal)       (elevated)            (hostile)
                              │               │               │
                          no action      start grace      immediate
                                         timer            response
                                              │
                                         timer expires
                                         without recovery
                                              │
                                         execute response
```

### 3.3 Scoring Model

**Primary model: Scaled Mahalanobis Distance**

For each feature vector `x` extracted from a typing window:

```
d(x) = sqrt( (x - μ)ᵀ Σ⁻¹ (x - μ) )
```

Where:
- `μ` = mean feature vector from enrollment.
- `Σ` = covariance matrix from enrollment (regularized to handle collinearity).

Mahalanobis distance is chosen over Euclidean because typing features are correlated
(fast typists have correlated fast dwell and flight times). The covariance structure
captures these correlations.

**Why not a neural network or deep learning model?**

1. Transparency. A Mahalanobis threshold is auditable. A neural net is not.
2. Data efficiency. 7–30 days of typing is thousands of samples — enough for robust
   statistical estimation, marginal for deep learning.
3. No training pipeline. No GPU requirement. No framework dependency.
4. Deterministic scoring. Same input always produces same score.
5. The adversary cannot study your model architecture because there is no architecture
   to reverse-engineer — only a mean vector and covariance matrix.

**Secondary model: Per-digraph Z-score ensemble**

For the top-N most frequent digraph classes, maintain individual univariate distributions.
Score each digraph independently. The ensemble score is the median Z-score across all
observed digraphs in the window. This catches adversaries who match global cadence but
fail on specific letter-pair timing.

**Combined score:**

```
S = α · mahalanobis_score + (1 - α) · digraph_ensemble_score
```

Default α = 0.6. Configurable. Both sub-scores normalized to [0, 1] via CDF of the
enrollment distribution (i.e., the score represents "how unlikely is this window under
the enrolled user's model").

### 3.4 Adaptive Baseline

Human typing varies with fatigue, time of day, and emotional state. SIGINT accounts for
this:

- **Time-of-day segmentation:** Enrollment builds separate sub-profiles for morning,
  afternoon, evening, and night (4 segments). Verification selects the closest temporal
  sub-profile.
- **Rolling micro-updates:** During verification, windows that score below 0.2 (strong
  match) are used to slightly update the profile (exponential moving average, λ = 0.005).
  This allows the profile to drift naturally with the user over months.
- **Fatigue detection:** Monotonically increasing dwell times over a session are not
  scored as identity deviation. The rate of change is compared against the user's own
  fatigue signature from enrollment.

**Micro-update poisoning defense:** If an adversary knows about micro-updates, they could
gradually shift the profile. Mitigation:
- Updates are only applied from windows scoring < 0.2 (deep match).
- Update rate λ is extremely small — shifting the profile meaningfully takes weeks of
  continuous, near-perfect impersonation.
- A frozen "anchor profile" from enrollment is stored separately and never updated. If the
  live profile drifts more than a configurable distance from the anchor, updates cease and
  an alert fires.

---

## 4. Enforcement Policy

### 4.1 Response Tiers

| Tier     | Trigger                           | Action                                | Reversible? |
|----------|-----------------------------------|---------------------------------------|-------------|
| AMBER    | Score > τ for > grace_duration    | Lock screen (loginctl lock-session)   | Yes         |
| RED      | Score > τ_crit immediately        | Lock + kill user sessions             | Yes*        |
| BLACK    | Score > τ_crit for > panic_dur    | LUKS wipe / secure erase              | **No**      |
| SILENT   | Any threshold breach              | Exfil dead-drop + continue silently   | N/A         |

*RED recovery requires re-authentication + a brief re-verification typing sample scored
against the anchor profile.

### 4.2 Policy Configuration

```toml
# /etc/sigint/policy.toml
# This file MUST be signed. Unsigned policy is rejected at boot.

[thresholds]
tau = 0.55                  # AMBER trigger (0.0–1.0)
tau_critical = 0.80         # RED trigger
grace_seconds = 45          # Time above tau before AMBER fires
panic_seconds = 120         # Time above tau_critical before BLACK fires

[enrollment]
min_days = 7
max_days = 30
min_daily_minutes = 30
auto_activate = false       # Require manual activation after enrollment

[response.amber]
action = "lock"

[response.red]
action = "lock_and_kill"
notify = false              # No visible notification to the operator

[response.black]
enabled = false             # Disabled by default. Opt-in only.
action = "wipe"
wipe_target = "/dev/nvme0n1"
wipe_method = "luks_nuke"   # Destroy LUKS header + first 10MB
confirm_delay = 5           # Seconds between decision and execution

[response.silent]
enabled = false
action = "dead_drop"
drop_target = "/var/lib/sigint/drops/"
drop_contents = ["screenshot", "process_list", "network_connections"]

[adaptive]
micro_update_lambda = 0.005
anchor_drift_max = 0.25
time_segments = 4

[scoring]
alpha = 0.6                 # Mahalanobis vs digraph ensemble weight
window_seconds = 30
min_events_per_window = 40  # Ignore sparse windows (user barely typing)
```

### 4.3 Policy Signing

Policy file is signed with Ed25519. The public key is compiled into `sigint-enforcer`
at build time (or loaded from a read-only path owned by root).

```
sigint-ctl policy sign --key /path/to/private.key --policy /etc/sigint/policy.toml
sigint-ctl policy verify --policy /etc/sigint/policy.toml
```

An adversary who gains root can replace the binary, but if they have root, SIGINT's
threat model is already violated. The signing prevents unprivileged policy tampering.

---

## 5. Enrollment Pipeline

### 5.1 Enrollment State Machine

```
                  sigint-ctl enroll start
                          │
                          ▼
                   ┌─────────────┐
                   │  COLLECTING  │◀──────── insufficient data
                   │              │           (loop daily)
                   └──────┬──────┘
                          │
                   daily quality check
                          │
                          ▼
                  ┌───────────────┐
              no  │  min_days met │
            ┌─────│  AND quality  │
            │     │  threshold?   │
            │     └───────┬───────┘
            │             │ yes
            ▼             ▼
       [COLLECTING]  ┌──────────┐
                     │  READY   │
                     └────┬─────┘
                          │
                   sigint-ctl enroll activate
                   (or auto if configured)
                          │
                          ▼
                     ┌──────────┐
                     │  ACTIVE  │
                     │ (verify) │
                     └──────────┘
```

### 5.2 Enrollment Quality Metrics

| Metric                    | Minimum for READY     | Ideal               |
|---------------------------|-----------------------|----------------------|
| Total keypress events     | 50,000                | 200,000+             |
| Unique digraph classes    | 80% of possible       | 95%+                 |
| Sessions (distinct days)  | 7                     | 14+                  |
| Per-segment coverage      | ≥ 2 segments with data| All 4 segments       |
| Feature variance ratio    | Intra-class CV < 0.3  | Intra-class CV < 0.2 |

### 5.3 Enrollment Data Storage

Profile store is a single file: `/var/lib/sigint/profiles/<uid>.profile`

Contents (all encrypted at rest with a key derived from the user's passphrase + machine-bound salt):
- Mean vector μ (per time segment)
- Covariance matrix Σ (per time segment, regularized)
- Anchor copy of μ and Σ (frozen)
- Per-digraph-class univariate distributions (mean, stddev, count)
- Enrollment metadata (start date, end date, quality scores, version)

**No raw keystroke data is persisted after feature extraction.** The raw event buffer
exists only in a tmpfs-backed ring buffer during collection and is zeroed on flush.

---

## 6. Wipe Mechanics (BLACK Response)

This is the most dangerous capability. It is opt-in, disabled by default, and designed
with multiple safeguards.

### 6.1 LUKS Nuke Method

1. Enforcer receives BLACK trigger.
2. Waits `confirm_delay` seconds (default 5). If score drops below τ during this window,
   abort. (Catches transient false positives.)
3. Opens `/dev/<wipe_target>` with O_DIRECT | O_SYNC.
4. Overwrites the first 10MB (LUKS header + key material) with random bytes from
   `/dev/urandom`.
5. Issues `BLKDISCARD` ioctl on the entire device (SSD TRIM — makes recovery infeasible
   on flash storage).
6. Calls `sync()`.
7. Issues `reboot(RB_POWER_OFF)` via syscall.

After step 4, the LUKS volume is irrecoverable without the header backup. If the user
has a header backup stored off-machine, the data is recoverable. If not, it is gone.

### 6.2 Wipe Safeguards

| Safeguard                   | Purpose                                          |
|-----------------------------|--------------------------------------------------|
| Disabled by default         | Cannot accidentally wipe.                        |
| Signed policy required      | Unprivileged users cannot enable wipe.            |
| confirm_delay               | Brief window to cancel via score recovery.        |
| τ_crit threshold            | Only extreme deviation triggers wipe path.        |
| panic_seconds duration      | Sustained anomaly required, not a single window.  |
| Separate AMBER/RED tiers    | Lock is always tried before wipe is considered.   |
| Build-time wipe cap         | sigint-enforcer can be compiled without wipe code. |
| Wipe audit log              | Written to separate device/partition before wipe.  |

### 6.3 False Positive Risk

With default thresholds (τ_crit = 0.80, panic_seconds = 120):

The false positive rate for a single 30-second window scoring > 0.80 is approximately
0.1% for the legitimate user (based on published keystroke dynamics literature — EER of
~2–5% for simpler models, Mahalanobis + ensemble is more discriminating).

The probability of **sustained** scoring > 0.80 across four consecutive windows (120s)
for the legitimate user is approximately (0.001)^4 = 10^-12 under independence
assumption. In practice, windows are correlated, so realistic estimate is ~10^-8.

This is acceptable for a mechanism that requires explicit opt-in and whose users
understand the stakes.

---

## 7. Privacy Architecture

### 7.1 Key-Class Pseudonymization

SIGINT never stores or transmits which letter was pressed. The collector maps each
physical key to one of ~12 key classes based on keyboard region:

```
┌─────────────────────────────────────────────┐
│  F-row          → class: FUNC               │
│  Number row     → class: NUM                │
│  QWERTY row     → class: UPPER_L, UPPER_R  │
│  ASDF row       → class: HOME_L, HOME_R    │
│  ZXCV row       → class: LOWER_L, LOWER_R  │
│  Modifiers      → class: MOD_L, MOD_R      │
│  Space          → class: SPACE              │
│  Punctuation    → class: PUNCT              │
│  Numpad         → class: NUMPAD             │
│  Navigation     → class: NAV               │
└─────────────────────────────────────────────┘
```

This means the stored profile contains timing patterns for digraphs like
`HOME_L → UPPER_R` — not `f → u`. An attacker who exfiltrates the profile cannot
reconstruct what was typed. They can only see that "a home-row-left key was pressed
for 85ms and then an upper-row-right key was pressed 120ms later."

### 7.2 Data Lifecycle

| Data                  | Storage Location | Retention                      | Encryption |
|-----------------------|------------------|--------------------------------|------------|
| Raw evdev events      | tmpfs ring buffer| Zeroed after feature extraction| N/A (RAM)  |
| Extracted features    | tmpfs            | Zeroed after model update/score| N/A (RAM)  |
| Profile (μ, Σ, etc.) | /var/lib/sigint/ | Until user deletes or re-enrolls| AES-256-GCM|
| Audit log             | /var/log/sigint/ | Configurable retention window  | At rest    |
| Policy file           | /etc/sigint/     | Until replaced                 | Signed     |
| Dead-drop captures    | /var/lib/sigint/ | Until manually retrieved       | AES-256-GCM|

### 7.3 What SIGINT Cannot Determine From Stored Data

- What was typed (key classes, not characters).
- Passwords (timing only, no content).
- URLs visited, commands executed, documents written.
- Anything beyond typing rhythm.

---

## 8. Implementation Constraints

### 8.1 Language

**Zig.**

Rationale:
- No runtime. No GC pauses affecting timing measurements.
- Comptime for compile-time policy embedding.
- C ABI compatibility for evdev/ioctl/syscall interfaces.
- Explicit allocation control — critical for zeroing sensitive buffers.
- No hidden allocations or exceptions.
- Small, auditable binaries.

### 8.2 Dependencies

| Dependency               | Purpose                          | Justification                  |
|--------------------------|----------------------------------|--------------------------------|
| Linux evdev API (kernel) | Keystroke capture                | Cannot be avoided.             |
| libsodium (or Zig port)  | Encryption, signing, KDF        | Vetted, minimal, audited.      |
| std.math / BLAS (Zig)    | Linear algebra for Mahalanobis  | Standard library preferred.    |

**No other dependencies.** No libc if avoidable (Zig can target freestanding Linux).

### 8.3 Capability Model

```
sigint-collector:
  - CAP_DAC_READ_SEARCH (to open /dev/input/eventN)
  - All other capabilities dropped at startup.
  - seccomp filter: read, write, ioctl (EVIOCGRAB), socket (AF_UNIX), exit_group.

sigint-analyzer:
  - No special capabilities.
  - seccomp filter: read, write, socket (AF_UNIX), mmap, munmap, exit_group.

sigint-enforcer:
  - CAP_SYS_BOOT (for reboot on BLACK).
  - CAP_SYS_ADMIN (for loginctl lock-session, session kill).
  - CAP_SYS_RAWIO (for direct device write on BLACK wipe).
  - All capabilities dropped after acquiring file descriptors at init.
  - seccomp filter: read, write, ioctl, reboot, socket (AF_UNIX), sync, exit_group.

sigint-ctl:
  - No special capabilities. Connects to analyzer/enforcer via Unix socket.
  - Operations gated by SO_PEERCRED UID check.
```

### 8.4 Systemd Integration

```ini
# sigint-collector.service
[Unit]
Description=SIGINT Keystroke Collector
After=systemd-udevd.service

[Service]
Type=notify
ExecStart=/usr/lib/sigint/sigint-collector
User=sigint-collector
Group=input
CapabilityBoundingSet=CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_DAC_READ_SEARCH
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateNetwork=true
RestrictNamespaces=true
SystemCallFilter=@basic-io @signal @timer
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
```

Similar hardened unit files for analyzer and enforcer, with appropriate capability sets.

### 8.5 Build Configuration

```
# build.zig flags

// Compile-time options:
// -Dwipe_support=true      Include BLACK response wipe code (default: false)
// -Dpolicy_pubkey=<path>   Embed policy verification public key
// -Dmax_window_ms=30000    Maximum scoring window in milliseconds
// -Dmin_events=40          Minimum events per scoring window
```

The wipe code path is a compile-time gate. Binaries built without `-Dwipe_support=true`
physically cannot execute wipe operations — the code does not exist in the binary.

---

## 9. Attack Surface Analysis

### 9.1 Attacks Against SIGINT Itself

| Attack Vector                         | Mitigation                                         |
|---------------------------------------|----------------------------------------------------|
| Kill the daemon                       | systemd watchdog restart; enforcer locks on death   |
| Modify the policy file                | Ed25519 signature verification                     |
| Inject synthetic evdev events         | EVIOCGRAB exclusive access in collector             |
| Poison the profile via micro-updates  | Anchor profile + drift ceiling                     |
| Exfiltrate the profile                | Encrypted at rest, no network sockets              |
| DoS the analyzer with input flood     | Rate limiting in collector, bounded buffer          |
| Race condition in score→action path   | Enforcer uses monotonic clock, atomic state machine |
| Tamper with Unix socket               | SO_PEERCRED + restrictive socket permissions        |

### 9.2 Enforcer Death Semantics

If `sigint-enforcer` crashes or is killed:

1. systemd restarts it (Restart=always, RestartSec=1).
2. If enforcer is down for > `enforcer_death_timeout` (default: 10s), the
   **collector** triggers a lock via a direct `loginctl lock-session` call
   (collector has a fallback lock capability for this case only).
3. Enforcer on restart loads last known score from shared memory segment. If stale
   (> 30s old), immediately enters AMBER until fresh scores arrive.

**Killing the enforcer locks the machine.** This is the dead man's switch property.

### 9.3 EVIOCGRAB Considerations

The collector uses `EVIOCGRAB` to obtain exclusive access to the input device. This
prevents other processes from reading raw events (blocking trivial keyloggers as a
side effect).

However, EVIOCGRAB also means the collector is the sole reader. If the collector crashes
without releasing the grab, the keyboard becomes unresponsive until the grab is released
(device close on process death handles this).

EVIOCGRAB is optional and configurable. In environments where other input consumers
exist (accessibility tools, custom keyboard daemons), it should be disabled. The
tradeoff: without EVIOCGRAB, an adversary process could read the same evdev events.

---

## 10. Operational Procedures

### 10.1 Initial Setup

```bash
# 1. Install
sudo make install    # Installs binaries, creates sigint-* users, sets up dirs

# 2. Generate policy signing keypair
sigint-ctl keygen --output /root/sigint-signing.key
# Store private key OFFLINE after signing. Do not leave on machine.

# 3. Configure policy
sudo vim /etc/sigint/policy.toml

# 4. Sign policy
sigint-ctl policy sign --key /root/sigint-signing.key --policy /etc/sigint/policy.toml

# 5. Start enrollment
sigint-ctl enroll start

# 6. Enable services
sudo systemctl enable --now sigint-collector sigint-analyzer sigint-enforcer

# 7. Type normally for 7–30 days

# 8. Check enrollment quality
sigint-ctl enroll status

# 9. Activate verification
sigint-ctl enroll activate
```

### 10.2 Status Monitoring

```bash
# Current score (requires same UID or root)
sigint-ctl status
# Output:
#   Mode:       VERIFY
#   Score:      0.12 (NORMAL)
#   Confidence: 0.94
#   Window:     182 events / 30s
#   Segment:    AFTERNOON
#   Profile:    v3, enrolled 2026-03-01, anchor drift: 0.08/0.25

# Enrollment quality during enrollment
sigint-ctl enroll status
# Output:
#   Day:        4/7
#   Events:     31,204
#   Digraph:    72% coverage
#   Segments:   MORNING(✓) AFTERNOON(✓) EVENING(✗) NIGHT(✗)
#   Quality:    NOT READY (need evening/night data and 3 more days)
```

### 10.3 Re-enrollment

If the user's typing changes significantly (injury, new keyboard, RSI accommodation):

```bash
sigint-ctl enroll reset    # Wipes current profile, enters COLLECTING
# Machine enters unenforced mode during re-enrollment
# Configure a manual lock/password during this window
```

### 10.4 Emergency Override

Physical presence authentication for when the legitimate user triggers a false positive:

```bash
# After AMBER/RED lock, at login screen:
# 1. Authenticate normally (password/key).
# 2. SIGINT presents a verification challenge: type a displayed sentence.
# 3. The challenge sample is scored against the ANCHOR profile (not live profile).
# 4. If anchor score < τ, session unlocks and live profile receives a correction.
# 5. If anchor score ≥ τ, lock persists. User must use recovery key.
```

Recovery key: a 256-bit key generated at enrollment, displayed once, and meant to be
written down and stored physically offline. This is the ultimate bypass.

---

## 11. Testing Strategy

### 11.1 Unit Tests

- Feature extraction: synthetic event streams with known timing → verify computed
  features match expected values to nanosecond precision.
- Scoring: synthetic feature vectors against known μ/Σ → verify Mahalanobis distance.
- Policy parsing: malformed TOML, missing fields, invalid ranges → verify rejection.
- Crypto: round-trip encrypt/decrypt of profile, signature verify/reject.

### 11.2 Integration Tests

- Full pipeline: collector → analyzer → enforcer with synthetic evdev input via uinput.
- Enrollment pipeline: run through full enrollment with synthetic user, verify profile.
- Lock trigger: verify loginctl lock-session is called when threshold exceeded.
- Enforcer death: kill enforcer, verify collector fallback lock engages.

### 11.3 Adversarial Tests

- Impersonation: train profile on User A, type as User B, verify detection.
- Replay: record User A's timing, replay via uinput, verify detection (replay lacks
  natural variance → should score anomalous on variance metrics).
- Profile poisoning: attempt micro-update drift over simulated weeks, verify anchor
  drift ceiling catches it.
- Resource exhaustion: flood collector with maximum event rate, verify bounded behavior.

### 11.4 Fuzz Targets

- evdev event parser (malformed events, truncated reads, out-of-order timestamps).
- Policy TOML parser.
- Profile deserialization.
- Unix socket protocol parser.

---

## 12. Known Limitations and Future Work

### 12.1 Current Limitations

1. **Single-user only.** Multi-user machines with shared physical keyboards need
   per-session isolation (possible via logind session tracking, not yet designed).

2. **Keyboard-only.** Touchpad, mouse dynamics, and touchscreen gestures are not
   captured. These are viable biometric channels for future versions.

3. **No Wayland input capture path.** Under Wayland, evdev access may be restricted.
   A Wayland input method or compositor plugin would be needed. X11/evdev is the
   initial target.

4. **Threshold tuning requires experimentation.** Default thresholds are educated
   guesses from literature. Per-user calibration (computing the user's own score
   distribution during enrollment) would be more robust.

5. **No multi-keyboard handling.** Users who switch between laptop and external
   keyboards will have different typing profiles. Sub-profile selection by detected
   HID device is architecturally possible but not yet designed.

### 12.2 Future Directions

- **Per-user threshold calibration** from enrollment score distribution.
- **Multi-keyboard sub-profiles** keyed by USB VID:PID.
- **Mouse/touchpad dynamics** as supplementary biometric channel.
- **Wayland compositor plugin** for post-X11 environments.
- **Remote attestation** of SIGINT status for fleet management.
- **Hardware security module integration** for profile key storage.
- **Cue integration** for edge deployment on Aether hardware.

---

## 13. References

1. Killourhy, K.S. and Maxion, R.A. (2009). "Comparing Anomaly-Detection Algorithms
   for Keystroke Dynamics." DSN 2009.
2. Monaco, J.V. et al. (2013). "Developing a Keystroke Biometric System for
   Continual Authentication of Computer Users." EuroISI 2013.
3. Zhong, Y. et al. (2012). "Keystroke Dynamics for User Authentication."
   IEEE CVPR Workshop.
4. NIST SP 800-63B, Section 5.2.3 — Biometric Authentication considerations.
5. Linux Input Subsystem documentation: kernel.org/doc/html/latest/input/

---

## Appendix A: Glossary

| Term              | Definition                                                        |
|-------------------|-------------------------------------------------------------------|
| Dwell time        | Key hold duration (press to release of same key)                  |
| Flight time       | Gap between releasing one key and pressing the next               |
| Digraph           | Two-key sequence (the fundamental unit of typing rhythm)          |
| Key class         | Pseudonymized keyboard region label (not the actual character)    |
| Anchor profile    | Frozen enrollment profile that never receives micro-updates       |
| τ (tau)           | AMBER threshold — score above this triggers initial response      |
| τ_crit            | RED/BLACK threshold — score above this triggers escalated response|
| EER               | Equal Error Rate — where FAR = FRR in biometric systems          |
| Dead man's switch | A mechanism that triggers when the expected operator is absent    |
| EVIOCGRAB         | Linux ioctl for exclusive access to an input device               |
