// Feature extraction engine.
//
// Converts a window of pseudonymized keystroke events into a feature vector
// suitable for Mahalanobis distance scoring. Features include dwell times,
// flight times, digraph latencies, error rates, burst cadence, and modifier
// hold ratios.
//
// The feature dimension is controlled by build_options.feature_dim (default 30):
// - Top 20 digraph mean latencies
// - 10 global features (mean/stddev dwell, mean/stddev flight, error rate,
//   burst cadence mean/stddev, pause mean/stddev, modifier hold ratio)

const std = @import("std");
const KeyClass = @import("key_class.zig").KeyClass;
const Event = @import("event.zig").Event;
const Direction = @import("event.zig").Direction;
const options = @import("build_options");

/// Number of possible key classes.
pub const num_classes: usize = @typeInfo(KeyClass).@"enum".fields.len;

/// Total number of possible digraphs (class pairs).
pub const num_digraphs: usize = num_classes * num_classes;

/// Feature vector dimension from build config.
pub const feature_dim: usize = options.feature_dim;

/// Number of digraph features = feature_dim - num_global_features.
pub const num_global_features: usize = 10;
pub const num_digraph_features: usize = feature_dim - num_global_features;

/// Canonical ordering of tracked digraphs, sorted by expected frequency.
/// These are the top digraph class-pairs we track for scoring.
/// Index into this array is the digraph's position in the feature vector.
pub const tracked_digraphs: [num_digraph_features]DigraphId = blk: {
    // Most common digraph patterns based on English typing frequency mapped
    // to key classes. Home-row pairs dominate due to QWERTY layout.
    var digraphs: [num_digraph_features]DigraphId = undefined;
    const pairs = [_][2]KeyClass{
        // Home row combinations (most stable, Tier 1)
        .{ .home_l, .home_r },
        .{ .home_r, .home_l },
        .{ .home_l, .home_l },
        .{ .home_r, .home_r },
        // Home-to-upper transitions
        .{ .home_l, .upper_r },
        .{ .home_r, .upper_l },
        .{ .upper_l, .home_r },
        .{ .upper_r, .home_l },
        // Upper row combinations
        .{ .upper_l, .upper_r },
        .{ .upper_r, .upper_l },
        // Home-to-lower transitions
        .{ .home_l, .lower_r },
        .{ .lower_l, .home_r },
        // Space transitions (very common)
        .{ .home_l, .space },
        .{ .home_r, .space },
        .{ .space, .home_l },
        .{ .space, .home_r },
        .{ .space, .upper_l },
        .{ .space, .upper_r },
        // Lower row combinations
        .{ .lower_l, .lower_r },
        .{ .lower_r, .lower_l },
    };
    for (pairs, 0..) |pair, i| {
        digraphs[i] = DigraphId.init(pair[0], pair[1]);
    }
    break :blk digraphs;
};

/// Compact identifier for a key-class digraph pair.
pub const DigraphId = struct {
    first: KeyClass,
    second: KeyClass,

    pub fn init(first: KeyClass, second: KeyClass) DigraphId {
        return .{ .first = first, .second = second };
    }

    pub fn index(self: DigraphId) usize {
        return @as(usize, @intFromEnum(self.first)) * num_classes + @intFromEnum(self.second);
    }

    pub fn eql(a: DigraphId, b: DigraphId) bool {
        return a.first == b.first and a.second == b.second;
    }
};

/// Per-digraph accumulator for online statistics.
const DigraphAccum = struct {
    sum: f64 = 0,
    sum_sq: f64 = 0,
    count: u32 = 0,

    fn update(self: *DigraphAccum, latency_ns: f64) void {
        self.sum += latency_ns;
        self.sum_sq += latency_ns * latency_ns;
        self.count += 1;
    }

    fn mean(self: DigraphAccum) f64 {
        if (self.count == 0) return 0;
        return self.sum / @as(f64, @floatFromInt(self.count));
    }

    fn stddev(self: DigraphAccum) f64 {
        if (self.count < 2) return 0;
        const n = @as(f64, @floatFromInt(self.count));
        const variance = (self.sum_sq - (self.sum * self.sum) / n) / (n - 1);
        return if (variance > 0) @sqrt(variance) else 0;
    }
};

/// The extracted feature vector for a single typing window.
pub const FeatureVector = struct {
    /// Combined feature array: [0..num_digraph_features) are digraph mean latencies,
    /// [num_digraph_features..feature_dim) are global features.
    values: [feature_dim]f64 = [_]f64{0} ** feature_dim,

    /// Per-digraph observation counts (for confidence weighting).
    digraph_counts: [num_digraph_features]u32 = [_]u32{0} ** num_digraph_features,

    /// Metadata
    window_start_ns: u64 = 0,
    window_end_ns: u64 = 0,
    total_events: u32 = 0,
    press_count: u32 = 0,

    /// Access digraph mean latency by tracked index.
    pub fn digraphLatency(self: *const FeatureVector, idx: usize) f64 {
        return self.values[idx];
    }

    /// Access global features by name.
    pub fn meanDwell(self: *const FeatureVector) f64 {
        return self.values[num_digraph_features + 0];
    }
    pub fn stddevDwell(self: *const FeatureVector) f64 {
        return self.values[num_digraph_features + 1];
    }
    pub fn meanFlight(self: *const FeatureVector) f64 {
        return self.values[num_digraph_features + 2];
    }
    pub fn stddevFlight(self: *const FeatureVector) f64 {
        return self.values[num_digraph_features + 3];
    }
    pub fn errorRate(self: *const FeatureVector) f64 {
        return self.values[num_digraph_features + 4];
    }
    pub fn burstCadenceMean(self: *const FeatureVector) f64 {
        return self.values[num_digraph_features + 5];
    }
    pub fn burstCadenceStddev(self: *const FeatureVector) f64 {
        return self.values[num_digraph_features + 6];
    }
    pub fn pauseMean(self: *const FeatureVector) f64 {
        return self.values[num_digraph_features + 7];
    }
    pub fn pauseStddev(self: *const FeatureVector) f64 {
        return self.values[num_digraph_features + 8];
    }
    pub fn modifierHoldRatio(self: *const FeatureVector) f64 {
        return self.values[num_digraph_features + 9];
    }
};

/// Threshold (in nanoseconds) separating burst typing from pauses.
/// 500ms = 500_000_000 ns.
const pause_threshold_ns: f64 = 500_000_000;

/// Extract a feature vector from a window of events.
/// Events must be sorted by timestamp. Returns the feature vector.
pub fn extractWindow(events: []const Event) FeatureVector {
    var fv = FeatureVector{};

    if (events.len < 2) {
        fv.total_events = @intCast(events.len);
        for (events) |ev| {
            if (ev.direction == .press) fv.press_count += 1;
        }
        return fv;
    }

    fv.window_start_ns = events[0].timestamp_ns;
    fv.window_end_ns = events[events.len - 1].timestamp_ns;
    fv.total_events = @intCast(events.len);

    // -- Accumulators --
    var dwell_sum: f64 = 0;
    var dwell_sum_sq: f64 = 0;
    var dwell_count: u32 = 0;

    var flight_sum: f64 = 0;
    var flight_sum_sq: f64 = 0;
    var flight_count: u32 = 0;

    var mod_dwell_sum: f64 = 0;
    var mod_dwell_count: u32 = 0;

    var error_count: u32 = 0;
    var press_count: u32 = 0;

    // Track pending presses per key class for dwell time computation.
    // Use the most recent press timestamp for each class.
    var pending_press: [num_classes]?u64 = [_]?u64{null} ** num_classes;
    var last_release: ?struct { class: KeyClass, timestamp_ns: u64 } = null;

    // Digraph accumulators for tracked pairs
    var digraph_accums: [num_digraph_features]DigraphAccum = [_]DigraphAccum{.{}} ** num_digraph_features;

    // Track last press for digraph computation
    var last_press: ?struct { class: KeyClass, timestamp_ns: u64 } = null;

    // Burst/pause interval accumulators
    var burst_sum: f64 = 0;
    var burst_sum_sq: f64 = 0;
    var burst_count: u32 = 0;
    var pause_sum: f64 = 0;
    var pause_sum_sq: f64 = 0;
    var pause_count: u32 = 0;

    for (events) |ev| {
        const class_idx = @intFromEnum(ev.key_class);

        switch (ev.direction) {
            .press => {
                press_count += 1;

                // Dwell: record press timestamp for matching with future release
                pending_press[class_idx] = ev.timestamp_ns;

                // Flight time: time from last release to this press
                if (last_release) |lr| {
                    if (ev.timestamp_ns > lr.timestamp_ns) {
                        const flight_ns: f64 = @floatFromInt(ev.timestamp_ns - lr.timestamp_ns);
                        flight_sum += flight_ns;
                        flight_sum_sq += flight_ns * flight_ns;
                        flight_count += 1;
                    }
                }

                // Digraph latency: press-to-press time
                if (last_press) |lp| {
                    if (ev.timestamp_ns > lp.timestamp_ns) {
                        const latency_ns: f64 = @floatFromInt(ev.timestamp_ns - lp.timestamp_ns);
                        const digraph = DigraphId.init(lp.class, ev.key_class);

                        // Check if this digraph is tracked
                        for (&digraph_accums, 0..) |*accum, i| {
                            if (tracked_digraphs[i].eql(digraph)) {
                                accum.update(latency_ns);
                                break;
                            }
                        }

                        // Burst vs pause classification
                        if (latency_ns < pause_threshold_ns) {
                            burst_sum += latency_ns;
                            burst_sum_sq += latency_ns * latency_ns;
                            burst_count += 1;
                        } else {
                            pause_sum += latency_ns;
                            pause_sum_sq += latency_ns * latency_ns;
                            pause_count += 1;
                        }
                    }
                }

                // Error detection: backspace/delete (nav class) following non-nav
                if (ev.key_class == .nav) {
                    if (last_press) |lp| {
                        if (lp.class != .nav) {
                            error_count += 1;
                        }
                    }
                }

                last_press = .{ .class = ev.key_class, .timestamp_ns = ev.timestamp_ns };
            },
            .release => {
                // Dwell time: press-to-release for same key class
                if (pending_press[class_idx]) |press_ts| {
                    if (ev.timestamp_ns > press_ts) {
                        const dwell_ns: f64 = @floatFromInt(ev.timestamp_ns - press_ts);
                        dwell_sum += dwell_ns;
                        dwell_sum_sq += dwell_ns * dwell_ns;
                        dwell_count += 1;

                        // Track modifier dwell separately for hold ratio
                        if (ev.key_class == .mod_l or ev.key_class == .mod_r) {
                            mod_dwell_sum += dwell_ns;
                            mod_dwell_count += 1;
                        }
                    }
                    pending_press[class_idx] = null;
                }

                last_release = .{ .class = ev.key_class, .timestamp_ns = ev.timestamp_ns };
            },
        }
    }

    fv.press_count = press_count;

    // -- Fill feature vector --

    // Digraph mean latencies (indices 0..num_digraph_features)
    for (&digraph_accums, 0..) |accum, i| {
        fv.values[i] = accum.mean();
        fv.digraph_counts[i] = accum.count;
    }

    // Global features (indices num_digraph_features..feature_dim)
    const g = num_digraph_features;

    // Mean/stddev dwell
    if (dwell_count > 0) {
        const n: f64 = @floatFromInt(dwell_count);
        fv.values[g + 0] = dwell_sum / n;
        if (dwell_count > 1) {
            const variance = (dwell_sum_sq - (dwell_sum * dwell_sum) / n) / (n - 1);
            fv.values[g + 1] = if (variance > 0) @sqrt(variance) else 0;
        }
    }

    // Mean/stddev flight
    if (flight_count > 0) {
        const n: f64 = @floatFromInt(flight_count);
        fv.values[g + 2] = flight_sum / n;
        if (flight_count > 1) {
            const variance = (flight_sum_sq - (flight_sum * flight_sum) / n) / (n - 1);
            fv.values[g + 3] = if (variance > 0) @sqrt(variance) else 0;
        }
    }

    // Error rate (errors per 100 key presses)
    if (press_count > 0) {
        fv.values[g + 4] = @as(f64, @floatFromInt(error_count)) / @as(f64, @floatFromInt(press_count)) * 100.0;
    }

    // Burst cadence mean/stddev
    if (burst_count > 0) {
        const n: f64 = @floatFromInt(burst_count);
        fv.values[g + 5] = burst_sum / n;
        if (burst_count > 1) {
            const variance = (burst_sum_sq - (burst_sum * burst_sum) / n) / (n - 1);
            fv.values[g + 6] = if (variance > 0) @sqrt(variance) else 0;
        }
    }

    // Pause mean/stddev
    if (pause_count > 0) {
        const n: f64 = @floatFromInt(pause_count);
        fv.values[g + 7] = pause_sum / n;
        if (pause_count > 1) {
            const variance = (pause_sum_sq - (pause_sum * pause_sum) / n) / (n - 1);
            fv.values[g + 8] = if (variance > 0) @sqrt(variance) else 0;
        }
    }

    // Modifier hold ratio: mean modifier dwell / mean overall dwell
    if (mod_dwell_count > 0 and dwell_count > 0) {
        const mod_mean = mod_dwell_sum / @as(f64, @floatFromInt(mod_dwell_count));
        const overall_mean = dwell_sum / @as(f64, @floatFromInt(dwell_count));
        if (overall_mean > 0) {
            fv.values[g + 9] = mod_mean / overall_mean;
        }
    }

    return fv;
}

// ---- Tests ----

test "empty window returns zero vector" {
    const events = [_]Event{};
    const fv = extractWindow(&events);
    try std.testing.expectEqual(@as(u32, 0), fv.total_events);
    for (fv.values) |v| {
        try std.testing.expectEqual(@as(f64, 0), v);
    }
}

test "single event returns zero features" {
    const events = [_]Event{
        .{ .key_class = .home_l, .direction = .press, .timestamp_ns = 1000 },
    };
    const fv = extractWindow(&events);
    try std.testing.expectEqual(@as(u32, 1), fv.total_events);
    try std.testing.expectEqual(@as(u32, 1), fv.press_count);
}

test "dwell time computation" {
    // Press at t=0, release at t=50ms → dwell = 50ms
    const events = [_]Event{
        .{ .key_class = .home_l, .direction = .press, .timestamp_ns = 0 },
        .{ .key_class = .home_l, .direction = .release, .timestamp_ns = 50_000_000 },
    };
    const fv = extractWindow(&events);
    // Mean dwell should be 50ms = 50_000_000 ns
    try std.testing.expectApproxEqAbs(@as(f64, 50_000_000), fv.meanDwell(), 0.1);
}

test "flight time computation" {
    // Release key A at t=50ms, press key B at t=80ms → flight = 30ms
    const events = [_]Event{
        .{ .key_class = .home_l, .direction = .press, .timestamp_ns = 0 },
        .{ .key_class = .home_l, .direction = .release, .timestamp_ns = 50_000_000 },
        .{ .key_class = .home_r, .direction = .press, .timestamp_ns = 80_000_000 },
        .{ .key_class = .home_r, .direction = .release, .timestamp_ns = 130_000_000 },
    };
    const fv = extractWindow(&events);
    // Flight: release(home_l)=50ms to press(home_r)=80ms → 30ms
    try std.testing.expectApproxEqAbs(@as(f64, 30_000_000), fv.meanFlight(), 0.1);
}

test "digraph latency for tracked pair" {
    // Press home_l at t=0, press home_r at t=100ms → digraph latency = 100ms
    const events = [_]Event{
        .{ .key_class = .home_l, .direction = .press, .timestamp_ns = 0 },
        .{ .key_class = .home_l, .direction = .release, .timestamp_ns = 50_000_000 },
        .{ .key_class = .home_r, .direction = .press, .timestamp_ns = 100_000_000 },
        .{ .key_class = .home_r, .direction = .release, .timestamp_ns = 150_000_000 },
    };
    const fv = extractWindow(&events);
    // Digraph (home_l → home_r) is tracked_digraphs[0]
    try std.testing.expectApproxEqAbs(@as(f64, 100_000_000), fv.digraphLatency(0), 0.1);
    try std.testing.expectEqual(@as(u32, 1), fv.digraph_counts[0]);
}

test "error rate detects backspace" {
    // Type a letter then backspace → error
    const events = [_]Event{
        .{ .key_class = .home_l, .direction = .press, .timestamp_ns = 0 },
        .{ .key_class = .home_l, .direction = .release, .timestamp_ns = 50_000_000 },
        .{ .key_class = .nav, .direction = .press, .timestamp_ns = 200_000_000 }, // backspace
        .{ .key_class = .nav, .direction = .release, .timestamp_ns = 250_000_000 },
    };
    const fv = extractWindow(&events);
    // 1 error out of 2 presses = 50 errors per 100 presses
    try std.testing.expectApproxEqAbs(@as(f64, 50.0), fv.errorRate(), 0.1);
}

test "burst vs pause classification" {
    // Two quick presses (burst) then a long pause then another press
    const events = [_]Event{
        .{ .key_class = .home_l, .direction = .press, .timestamp_ns = 0 },
        .{ .key_class = .home_l, .direction = .release, .timestamp_ns = 50_000_000 },
        .{ .key_class = .home_r, .direction = .press, .timestamp_ns = 100_000_000 }, // 100ms after first press = burst
        .{ .key_class = .home_r, .direction = .release, .timestamp_ns = 150_000_000 },
        .{ .key_class = .home_l, .direction = .press, .timestamp_ns = 700_000_000 }, // 600ms after second press = pause
        .{ .key_class = .home_l, .direction = .release, .timestamp_ns = 750_000_000 },
    };
    const fv = extractWindow(&events);
    // Burst: 100ms interval (home_l→home_r)
    try std.testing.expectApproxEqAbs(@as(f64, 100_000_000), fv.burstCadenceMean(), 0.1);
    // Pause: 600ms interval (home_r→home_l)
    try std.testing.expectApproxEqAbs(@as(f64, 600_000_000), fv.pauseMean(), 0.1);
}
