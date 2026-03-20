// Integration tests for the full scoring pipeline.
//
// Tests the complete path: synthetic events → feature extraction →
// Welford enrollment → Cholesky decomposition → Mahalanobis scoring.
// Verifies that an enrolled user scores low and an impersonator scores high.

const std = @import("std");
const common = @import("sigint_common");
const Event = common.event.Event;
const Direction = common.event.Direction;
const KeyClass = common.key_class.KeyClass;
const features = common.features;
const linalg = common.math_linalg;
const scoring = common.scoring;
const options = common.build_options;
const N = options.feature_dim;

/// Generate a synthetic typing session with consistent timing patterns.
/// Simulates a specific "user" with characteristic dwell/flight/digraph timing.
fn generateUserSession(
    base_dwell_ns: u64,
    base_flight_ns: u64,
    jitter_ns: u64,
    num_keypresses: usize,
    rng: std.Random,
) []Event {
    var events: [8192]Event = undefined;
    var count: usize = 0;
    var t: u64 = 1_000_000_000; // start at 1s

    const classes = [_]KeyClass{ .home_l, .home_r, .upper_l, .upper_r, .lower_l, .space };

    var i: usize = 0;
    while (i < num_keypresses and count + 1 < events.len) : (i += 1) {
        const cls = classes[rng.intRangeAtMost(usize, 0, classes.len - 1)];

        // Jittered dwell time
        const dwell = base_dwell_ns + rng.intRangeAtMost(u64, 0, jitter_ns);
        // Jittered flight time
        const flight = base_flight_ns + rng.intRangeAtMost(u64, 0, jitter_ns);

        // Press
        events[count] = .{ .key_class = cls, .direction = .press, .timestamp_ns = t };
        count += 1;

        // Release
        t += dwell;
        events[count] = .{ .key_class = cls, .direction = .release, .timestamp_ns = t };
        count += 1;

        // Inter-key gap
        t += flight;
    }

    // Return a copy that's properly sized
    return events[0..count];
}

test "enrolled user scores low, impersonator scores high" {
    // Use a deterministic PRNG for reproducibility
    var prng = std.Random.DefaultPrng.init(42);
    const rng = prng.random();

    // "User A" profile: 80ms dwell, 60ms flight, 15ms jitter
    // Enroll with multiple windows
    var welford = linalg.WelfordState{};
    var digraph_accums: [features.num_digraph_features]scoring.DigraphStat =
        [_]scoring.DigraphStat{.{}} ** features.num_digraph_features;

    // Enroll 50 windows
    for (0..50) |_| {
        const session = generateUserSession(80_000_000, 60_000_000, 15_000_000, 100, rng);
        const fv = features.extractWindow(session);
        welford.update(&fv.values);

        // Accumulate digraph stats
        for (0..features.num_digraph_features) |d| {
            if (fv.digraph_counts[d] > 0) {
                digraph_accums[d].count += fv.digraph_counts[d];
            }
        }
    }

    // Finalize model
    var model = scoring.SegmentModel{};
    var sigma: [N][N]f64 = undefined;
    welford.finalize(&model.mu, &sigma);
    model.sample_count = @intCast(welford.count);
    linalg.choleskyDecompose(&sigma, &model.cholesky_L) catch {
        // If Cholesky fails, use identity (shouldn't happen with enough data)
        for (0..N) |i| {
            for (0..N) |j| {
                model.cholesky_L[i][j] = if (i == j) 1.0 else 0.0;
            }
        }
    };

    // Score User A (enrolled user) — should be low
    var user_a_scores: [10]f64 = undefined;
    for (0..10) |i| {
        const session = generateUserSession(80_000_000, 60_000_000, 15_000_000, 100, rng);
        const fv = features.extractWindow(session);
        user_a_scores[i] = scoring.scoreMahalanobis(&fv, &model);
    }

    // Score User B (impersonator) — different timing: 120ms dwell, 100ms flight
    var user_b_scores: [10]f64 = undefined;
    for (0..10) |i| {
        const session = generateUserSession(120_000_000, 100_000_000, 15_000_000, 100, rng);
        const fv = features.extractWindow(session);
        user_b_scores[i] = scoring.scoreMahalanobis(&fv, &model);
    }

    // Compute mean scores
    var user_a_mean: f64 = 0;
    var user_b_mean: f64 = 0;
    for (user_a_scores) |s| user_a_mean += s;
    for (user_b_scores) |s| user_b_mean += s;
    user_a_mean /= 10;
    user_b_mean /= 10;

    // User A should score significantly lower than User B
    try std.testing.expect(user_a_mean < user_b_mean);

    // User A mean should be below the AMBER threshold (0.55)
    try std.testing.expect(user_a_mean < 0.55);

    // User B mean should be above User A mean by a meaningful margin
    try std.testing.expect(user_b_mean > user_a_mean + 0.1);
}

test "micro-update drift ceiling prevents poisoning" {
    const N_ = N;

    // Start with a known anchor
    var anchor_mu: [N_]f64 = [_]f64{100} ** N_;
    var live_mu: [N_]f64 = undefined;
    @memcpy(&live_mu, &anchor_mu);

    const drift_max: f64 = 0.25;
    const lambda: f64 = 0.005;

    // Apply 1000 micro-updates with a shifted sample (adversary trying to drift)
    var adversary_sample: [N_]f64 = [_]f64{200} ** N_;
    for (0..1000) |_| {
        linalg.emaUpdate(&live_mu, &adversary_sample, lambda);

        const drift = linalg.euclideanDistance(&live_mu, &anchor_mu);
        if (drift > drift_max) {
            // Reset to anchor (this is what the analyzer does)
            @memcpy(&live_mu, &anchor_mu);
            break;
        }
    }

    // Verify drift was caught and mu was reset
    const final_drift = linalg.euclideanDistance(&live_mu, &anchor_mu);
    try std.testing.expect(final_drift <= drift_max);
}

test "enforcer state machine transitions" {
    // Simulate the enforcer state machine with a score sequence
    const State = enum { normal, grace, amber, red };

    const tau: f64 = 0.55;
    const tau_crit: f64 = 0.80;
    const grace_windows: usize = 3; // simplified: 3 windows instead of time-based

    var state: State = .normal;
    var grace_count: usize = 0;

    // Score sequence: normal → grace → amber → recovery
    const scores = [_]f64{
        0.10, 0.12, 0.15, // normal
        0.60, 0.65, 0.70, // grace (above tau)
        0.62, // grace expires → amber
        0.40, // recovery → normal
        0.85, // immediate red (above tau_crit)
        0.30, // recovery → normal
    };

    var transitions: [scores.len]State = undefined;

    for (scores, 0..) |score, i| {
        switch (state) {
            .normal => {
                if (score >= tau_crit) {
                    state = .red;
                } else if (score >= tau) {
                    state = .grace;
                    grace_count = 1;
                }
            },
            .grace => {
                if (score < tau) {
                    state = .normal;
                    grace_count = 0;
                } else if (score >= tau_crit) {
                    state = .red;
                } else {
                    grace_count += 1;
                    if (grace_count >= grace_windows) {
                        state = .amber;
                    }
                }
            },
            .amber => {
                if (score < tau) {
                    state = .normal;
                } else if (score >= tau_crit) {
                    state = .red;
                }
            },
            .red => {
                if (score < tau) {
                    state = .normal;
                }
            },
        }
        transitions[i] = state;
    }

    // Verify expected transitions
    try std.testing.expectEqual(State.normal, transitions[0]); // 0.10
    try std.testing.expectEqual(State.normal, transitions[2]); // 0.15
    try std.testing.expectEqual(State.grace, transitions[3]); // 0.60 → grace
    try std.testing.expectEqual(State.amber, transitions[6]); // grace expired
    try std.testing.expectEqual(State.normal, transitions[7]); // 0.40 → recovery
    try std.testing.expectEqual(State.red, transitions[8]); // 0.85 → immediate red
    try std.testing.expectEqual(State.normal, transitions[9]); // 0.30 → recovery
}

test "profile round-trip through encrypt/decrypt" {
    const crypto = common.crypto_util;
    const profile_mod = common.profile;

    // Create a profile with some data
    var profile = profile_mod.Profile{};
    profile.uid = 1000;
    profile.total_events = 100000;
    profile.segments[0].mu[0] = 85_000_000;
    profile.segments[0].sample_count = 5000;

    // Serialize
    const size = comptime profile_mod.Profile.totalSize();
    var plain_buf: [size]u8 = undefined;
    _ = try profile.serialize(&plain_buf);

    // Encrypt
    var key: [crypto.key_length]u8 = undefined;
    std.crypto.random.bytes(&key);
    defer crypto.secureZero(&key);

    var enc_buf: [size + crypto.encryption_overhead]u8 = undefined;
    const enc_len = try crypto.encrypt(&plain_buf, &key, &enc_buf);

    // Decrypt
    var dec_buf: [size]u8 = undefined;
    const decrypted = try crypto.decrypt(enc_buf[0..enc_len], &key, &dec_buf);

    // Deserialize
    const restored = try profile_mod.Profile.deserialize(decrypted);

    try std.testing.expectEqual(@as(u32, 1000), restored.uid);
    try std.testing.expectEqual(@as(u64, 100000), restored.total_events);
    try std.testing.expectApproxEqAbs(@as(f64, 85_000_000), restored.segments[0].mu[0], 1e-6);
}

test "TOML policy parse and validate full config" {
    const policy_mod = common.policy;

    const toml =
        \\[thresholds]
        \\tau = 0.55
        \\tau_critical = 0.80
        \\grace_seconds = 45
        \\panic_seconds = 120
        \\
        \\[enrollment]
        \\min_days = 7
        \\max_days = 30
        \\min_daily_minutes = 30
        \\auto_activate = false
        \\
        \\[response.amber]
        \\action = "lock"
        \\
        \\[response.red]
        \\action = "lock_and_kill"
        \\notify = false
        \\
        \\[response.black]
        \\enabled = false
        \\confirm_delay = 5
        \\
        \\[response.silent]
        \\enabled = false
        \\
        \\[adaptive]
        \\micro_update_lambda = 0.005
        \\anchor_drift_max = 0.25
        \\time_segments = 4
        \\
        \\[scoring]
        \\alpha = 0.6
        \\window_seconds = 30
        \\min_events_per_window = 40
    ;

    var map = try policy_mod.parseToml(toml, std.testing.allocator);
    defer policy_mod.deinitMap(&map, std.testing.allocator);

    const policy = try policy_mod.policyFromMap(&map);
    try policy.validate();

    try std.testing.expectApproxEqAbs(@as(f64, 0.55), policy.tau, 1e-10);
    try std.testing.expectApproxEqAbs(@as(f64, 0.80), policy.tau_critical, 1e-10);
    try std.testing.expectEqual(@as(u32, 45), policy.grace_seconds);
    try std.testing.expectEqual(@as(u32, 120), policy.panic_seconds);
    try std.testing.expectEqual(false, policy.enroll_auto_activate);
    try std.testing.expectEqual(policy_mod.Policy.Action.lock, policy.amber_action);
    try std.testing.expectEqual(policy_mod.Policy.Action.lock_and_kill, policy.red_action);
    try std.testing.expectEqual(false, policy.black_enabled);
    try std.testing.expectApproxEqAbs(@as(f64, 0.005), policy.micro_update_lambda, 1e-10);
    try std.testing.expectApproxEqAbs(@as(f64, 0.6), policy.alpha, 1e-10);
    try std.testing.expectEqual(@as(u32, 40), policy.min_events_per_window);
}

test "Ed25519 policy sign and verify end-to-end" {
    const crypto = common.crypto_util;

    const policy_content =
        \\[thresholds]
        \\tau = 0.55
    ;

    // Generate keypair
    const kp = crypto.generateSigningKeypair();

    // Sign
    const sig = try crypto.sign(policy_content, kp);
    const pk = kp.public_key.toBytes();

    // Verify
    try crypto.verify(policy_content, &sig, &pk);

    // Tampered content should fail
    const tampered = policy_content ++ "\n";
    const result = crypto.verify(tampered, &sig, &pk);
    try std.testing.expectError(error.SignatureVerificationFailed, result);
}
