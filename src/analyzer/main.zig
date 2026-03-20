// sigint-analyzer: Keystroke biometric analysis daemon.
//
// Receives pseudonymized keystroke events from the collector, builds
// a biometric profile during enrollment, and continuously scores
// typing sessions against that profile during verification. Emits
// score messages to the enforcer.
//
// State machine: IDLE → ENROLLING → READY → VERIFYING
//
// No special capabilities required. Runs as unprivileged user.

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const common = @import("sigint_common");
const Event = common.event.Event;
const Direction = common.event.Direction;
const features_mod = common.features;
const scoring = common.scoring;
const linalg = common.math_linalg;
const ipc = common.ipc;
const protocol = common.protocol;
const profile_mod = common.profile;
const crypto_util = common.crypto_util;
const time_segment = common.time_segment;
const options = common.build_options;

const N = options.feature_dim;
const version = "0.1.0";

/// Default run directory for sockets.
const default_run_dir = "/run/sigint";
const default_profile_dir = "/var/lib/sigint/profiles";

/// Analyzer operating mode.
const Mode = enum(u8) {
    idle,
    enrolling,
    ready,
    verifying,
};

/// Configuration from command-line arguments.
const Config = struct {
    collector_socket: []const u8 = default_run_dir ++ "/collector.sock",
    ctl_socket: []const u8 = default_run_dir ++ "/analyzer-ctl.sock",
    enforcer_socket: []const u8 = default_run_dir ++ "/enforcer.sock",
    profile_dir: []const u8 = default_profile_dir,
    dry_run: bool = false,
    window_seconds: u32 = 30,
    min_events: u32 = 40,
    alpha: f64 = 0.6,
    micro_update_lambda: f64 = 0.005,
    anchor_drift_max: f64 = 0.25,
    run_dir: []const u8 = default_run_dir,
};

/// Sliding window of recent events for feature extraction.
const EventWindow = struct {
    events: [4096]Event = undefined,
    count: usize = 0,
    head: usize = 0, // ring buffer write position

    fn push(self: *EventWindow, ev: Event) void {
        if (self.count < self.events.len) {
            self.events[self.count] = ev;
            self.count += 1;
        } else {
            // Ring buffer full — overwrite oldest
            self.events[self.head] = ev;
            self.head = (self.head + 1) % self.events.len;
        }
    }

    /// Get events within the last `window_ns` nanoseconds.
    /// Returns a slice of events (may not be contiguous in ring buffer,
    /// so we copy to a provided output buffer).
    fn getWindow(self: *const EventWindow, window_ns: u64, out: []Event) usize {
        if (self.count == 0) return 0;

        const now = self.events[(self.head + self.count - 1) % self.events.len].timestamp_ns;
        const cutoff = if (now > window_ns) now - window_ns else 0;

        var out_count: usize = 0;
        // Iterate from oldest to newest
        var i: usize = 0;
        while (i < self.count and out_count < out.len) : (i += 1) {
            const idx = (self.head + i) % self.events.len;
            if (self.events[idx].timestamp_ns >= cutoff) {
                out[out_count] = self.events[idx];
                out_count += 1;
            }
        }
        return out_count;
    }

    fn clear(self: *EventWindow) void {
        self.count = 0;
        self.head = 0;
    }
};

/// Enrollment state tracking.
const EnrollmentState = struct {
    welford: [4]linalg.WelfordState = [_]linalg.WelfordState{.{}} ** 4,
    digraph_accums: [4][features_mod.num_digraph_features]DigraphAccum =
        [_][features_mod.num_digraph_features]DigraphAccum{
        [_]DigraphAccum{.{}} ** features_mod.num_digraph_features,
    } ** 4,
    total_events: u64 = 0,
    start_time: i64 = 0,
    days_seen: [30]bool = [_]bool{false} ** 30, // track unique days
    segment_event_count: [4]u64 = [_]u64{0} ** 4,
    windows_processed: u64 = 0,
};

const DigraphAccum = struct {
    sum: f64 = 0,
    sum_sq: f64 = 0,
    count: u32 = 0,

    fn update(self: *DigraphAccum, val: f64) void {
        self.sum += val;
        self.sum_sq += val * val;
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

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const config = parseArgs(args) orelse return;

    runAnalyzer(config, allocator) catch |err| {
        logErr("fatal: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn parseArgs(args: []const []const u8) ?Config {
    var config = Config{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--version")) {
            writeOut("sigint-analyzer {s}\n", .{version});
            return null;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            writeOut(
                \\sigint-analyzer {s} — keystroke biometric analyzer
                \\
                \\Usage: sigint-analyzer [OPTIONS]
                \\
                \\Options:
                \\  --run-dir PATH           Socket directory (default: {s})
                \\  --collector-socket PATH  Socket for collector events
                \\  --ctl-socket PATH        Socket for ctl commands
                \\  --enforcer-socket PATH   Socket for score output
                \\  --profile-dir PATH       Profile storage directory
                \\  --dry-run                Log scores instead of sending to enforcer
                \\  --version                Show version
                \\  --help                   Show this help
                \\
            , .{ version, default_run_dir });
            return null;
        } else if (std.mem.eql(u8, arg, "--collector-socket")) {
            i += 1;
            if (i >= args.len) return null;
            config.collector_socket = args[i];
        } else if (std.mem.eql(u8, arg, "--ctl-socket")) {
            i += 1;
            if (i >= args.len) return null;
            config.ctl_socket = args[i];
        } else if (std.mem.eql(u8, arg, "--enforcer-socket")) {
            i += 1;
            if (i >= args.len) return null;
            config.enforcer_socket = args[i];
        } else if (std.mem.eql(u8, arg, "--profile-dir")) {
            i += 1;
            if (i >= args.len) return null;
            config.profile_dir = args[i];
        } else if (std.mem.eql(u8, arg, "--run-dir")) {
            i += 1;
            if (i >= args.len) return null;
            config.run_dir = args[i];
        } else if (std.mem.eql(u8, arg, "--dry-run")) {
            config.dry_run = true;
        } else {
            logErr("unknown argument: {s}\n", .{arg});
            return null;
        }
    }
    return config;
}

fn runAnalyzer(config_in: Config, allocator: std.mem.Allocator) !void {
    var config = config_in;

    // Derive socket paths from run-dir if they weren't explicitly overridden
    if (std.mem.eql(u8, config.run_dir, default_run_dir) == false) {
        var buf1: [256]u8 = undefined;
        var buf2: [256]u8 = undefined;
        var buf3: [256]u8 = undefined;
        const s1 = std.fmt.bufPrint(&buf1, "{s}/collector.sock", .{config.run_dir}) catch return error.PathTooLong;
        const s2 = std.fmt.bufPrint(&buf2, "{s}/analyzer-ctl.sock", .{config.run_dir}) catch return error.PathTooLong;
        const s3 = std.fmt.bufPrint(&buf3, "{s}/enforcer.sock", .{config.run_dir}) catch return error.PathTooLong;
        config.collector_socket = try allocator.dupe(u8, s1);
        config.ctl_socket = try allocator.dupe(u8, s2);
        config.enforcer_socket = try allocator.dupe(u8, s3);
    }

    var mode: Mode = .idle;
    var event_window = EventWindow{};
    var enrollment = EnrollmentState{};
    var profile = profile_mod.Profile{};
    var enforcer_fd: ?posix.socket_t = null;

    // Track when we last scored (avoid scoring too frequently)
    var last_score_ns: u64 = 0;
    const score_interval_ns: u64 = @as(u64, config.window_seconds) * std.time.ns_per_s / 2;

    // Create listener socket for collector connections
    const collector_listen_fd = ipc.createServer(config.collector_socket) catch |err| {
        logErr("cannot create collector socket at {s}: {s}\n", .{ config.collector_socket, @errorName(err) });
        return err;
    };
    defer ipc.close(collector_listen_fd);

    // Create listener socket for ctl connections
    const ctl_listen_fd = ipc.createServer(config.ctl_socket) catch |err| {
        logErr("cannot create ctl socket at {s}: {s}\n", .{ config.ctl_socket, @errorName(err) });
        return err;
    };
    defer ipc.close(ctl_listen_fd);

    logErr("analyzer running (mode: idle)\n", .{});

    // Connect to enforcer if not dry-run
    if (!config.dry_run) {
        enforcer_fd = ipc.connectToServer(config.enforcer_socket) catch null;
        if (enforcer_fd != null) {
            logErr("connected to enforcer\n", .{});
        }
    }
    defer if (enforcer_fd) |fd| ipc.close(fd);

    // Main event loop using poll
    var collector_fd: ?posix.socket_t = null;
    defer if (collector_fd) |fd| ipc.close(fd);
    var ctl_fd: ?posix.socket_t = null;
    defer if (ctl_fd) |fd| ipc.close(fd);

    var recv_buf: [protocol.header_size + protocol.max_payload_size]u8 = undefined;

    while (true) {
        // Build poll fd set
        var poll_fds: [4]linux.pollfd = undefined;
        var poll_count: usize = 0;

        // Always poll listener sockets
        poll_fds[poll_count] = .{ .fd = collector_listen_fd, .events = linux.POLL.IN, .revents = 0 };
        const collector_listen_idx = poll_count;
        poll_count += 1;

        poll_fds[poll_count] = .{ .fd = ctl_listen_fd, .events = linux.POLL.IN, .revents = 0 };
        const ctl_listen_idx = poll_count;
        poll_count += 1;

        // Poll connected collector if present
        var collector_data_idx: ?usize = null;
        if (collector_fd) |cfd| {
            poll_fds[poll_count] = .{ .fd = cfd, .events = linux.POLL.IN, .revents = 0 };
            collector_data_idx = poll_count;
            poll_count += 1;
        }

        // Poll connected ctl if present
        var ctl_data_idx: ?usize = null;
        if (ctl_fd) |cfd| {
            poll_fds[poll_count] = .{ .fd = cfd, .events = linux.POLL.IN, .revents = 0 };
            ctl_data_idx = poll_count;
            poll_count += 1;
        }

        const poll_result = linux.poll(&poll_fds, @intCast(poll_count), 1000);
        if (poll_result < 0) continue;

        // Accept new collector connection
        if (poll_fds[collector_listen_idx].revents & linux.POLL.IN != 0) {
            if (collector_fd) |old| ipc.close(old);
            collector_fd = ipc.acceptClient(collector_listen_fd) catch null;
            if (collector_fd != null) logErr("collector connected\n", .{});
        }

        // Accept new ctl connection
        if (poll_fds[ctl_listen_idx].revents & linux.POLL.IN != 0) {
            if (ctl_fd) |old| ipc.close(old);
            ctl_fd = ipc.acceptClient(ctl_listen_fd) catch null;
            if (ctl_fd != null) logErr("ctl connected\n", .{});
        }

        // Handle collector data
        if (collector_data_idx) |idx| {
            if (poll_fds[idx].revents & linux.POLL.IN != 0) {
                const frame = ipc.recvFrame(collector_fd.?, &recv_buf) catch {
                    logErr("collector disconnected\n", .{});
                    ipc.close(collector_fd.?);
                    collector_fd = null;
                    continue;
                };

                if (frame.msg_type == .event_batch) {
                    processEventBatch(
                        frame.payload,
                        &event_window,
                        &mode,
                        &enrollment,
                        &profile,
                        &enforcer_fd,
                        &last_score_ns,
                        score_interval_ns,
                        config,
                    );
                }
            }
            if (collector_data_idx) |cidx| {
                if (poll_fds[cidx].revents & (linux.POLL.HUP | linux.POLL.ERR) != 0) {
                    logErr("collector disconnected\n", .{});
                    if (collector_fd) |fd| ipc.close(fd);
                    collector_fd = null;
                }
            }
        }

        // Handle ctl data
        if (ctl_data_idx) |idx| {
            if (poll_fds[idx].revents & linux.POLL.IN != 0) {
                const frame = ipc.recvFrame(ctl_fd.?, &recv_buf) catch {
                    ipc.close(ctl_fd.?);
                    ctl_fd = null;
                    continue;
                };

                if (frame.msg_type == .ctl_request) {
                    handleCtlRequest(frame.payload, &mode, &enrollment, &profile, &event_window, ctl_fd.?, config);
                }
            }
            if (ctl_data_idx) |cidx| {
                if (poll_fds[cidx].revents & (linux.POLL.HUP | linux.POLL.ERR) != 0) {
                    if (ctl_fd) |fd| ipc.close(fd);
                    ctl_fd = null;
                }
            }
        }
    }
}

fn processEventBatch(
    payload: []const u8,
    window: *EventWindow,
    mode: *Mode,
    enrollment: *EnrollmentState,
    profile: *profile_mod.Profile,
    enforcer_fd: *?posix.socket_t,
    last_score_ns: *u64,
    score_interval_ns: u64,
    config: Config,
) void {
    var events: [256]Event = undefined;
    const result = Event.deserializeBatch(payload, &events) catch return;

    for (events[0..result.count]) |ev| {
        window.push(ev);

        switch (mode.*) {
            .enrolling => {
                enrollment.total_events += 1;
            },
            .verifying => {
                // Score periodically
                if (ev.timestamp_ns > last_score_ns.* + score_interval_ns) {
                    scoreAndEmit(window, profile, enforcer_fd, config);
                    last_score_ns.* = ev.timestamp_ns;
                }
            },
            .idle, .ready => {},
        }
    }

    // During enrollment, process complete windows for feature accumulation
    if (mode.* == .enrolling and window.count >= config.min_events) {
        enrollWindow(window, enrollment);
    }
}

fn enrollWindow(window: *EventWindow, enrollment: *EnrollmentState) void {
    // Extract features from current window
    var window_events: [4096]Event = undefined;
    const count = window.getWindow(30 * std.time.ns_per_s, &window_events);
    if (count < 20) return;

    const fv = features_mod.extractWindow(window_events[0..count]);
    if (fv.press_count < 10) return;

    // Determine time segment
    const epoch = std.time.timestamp();
    const hour: u5 = @intCast(@divTrunc(@mod(epoch, 86400), 3600));
    const seg = @intFromEnum(time_segment.segment(hour));

    // Update Welford accumulator for this segment
    enrollment.welford[seg].update(&fv.values);
    enrollment.segment_event_count[seg] += fv.total_events;

    // Update per-digraph accumulators
    for (0..features_mod.num_digraph_features) |i| {
        if (fv.digraph_counts[i] > 0) {
            enrollment.digraph_accums[seg][i].update(fv.values[i]);
        }
    }

    enrollment.windows_processed += 1;

    if (enrollment.windows_processed % 100 == 0) {
        logErr("enrollment: {d} windows, {d} total events\n", .{
            enrollment.windows_processed,
            enrollment.total_events,
        });
    }
}

fn scoreAndEmit(
    window: *EventWindow,
    profile: *profile_mod.Profile,
    enforcer_fd: *?posix.socket_t,
    config: Config,
) void {
    // Extract features from current window
    var window_events: [4096]Event = undefined;
    const window_ns = @as(u64, config.window_seconds) * std.time.ns_per_s;
    const count = window.getWindow(window_ns, &window_events);
    if (count < config.min_events) return;

    const fv = features_mod.extractWindow(window_events[0..count]);
    if (fv.press_count < config.min_events / 2) return;

    // Determine time segment
    const epoch = std.time.timestamp();
    const hour: u5 = @intCast(@divTrunc(@mod(epoch, 86400), 3600));
    const seg = @intFromEnum(time_segment.segment(hour));

    const model = &profile.segments[seg];

    // Score
    const mahal_score = scoring.scoreMahalanobis(&fv, model);
    const digraph_score = scoring.scoreDigraphEnsemble(&fv, model);
    const window_score = scoring.scoreCombined(mahal_score, digraph_score, config.alpha);

    // Confidence based on event count vs minimum
    const confidence: f32 = @floatCast(@min(1.0, @as(f64, @floatFromInt(fv.press_count)) / @as(f64, @floatFromInt(config.min_events))));

    // Micro-update: if strong match, slightly adapt live profile
    if (window_score < 0.2 and model.sample_count > 0) {
        linalg.emaUpdate(&profile.segments[seg].mu, &fv.values, config.micro_update_lambda);

        // Check anchor drift
        const drift = linalg.euclideanDistance(&profile.segments[seg].mu, &profile.anchor_segments[seg].mu);
        if (drift > config.anchor_drift_max) {
            logErr("WARNING: anchor drift {d:.4} exceeds max {d:.4}, freezing updates\n", .{
                drift,
                config.anchor_drift_max,
            });
            // Reset live mu to anchor to prevent further drift
            profile.segments[seg].mu = profile.anchor_segments[seg].mu;
        }
    }

    if (config.dry_run) {
        logErr("score: {d:.4} (mahal={d:.4} digraph={d:.4} conf={d:.2} seg={d})\n", .{
            window_score,
            mahal_score,
            digraph_score,
            confidence,
            seg,
        });
        return;
    }

    // Emit score to enforcer
    if (enforcer_fd.*) |efd| {
        const score_msg = protocol.ScorePayload{
            .timestamp_ns = @intCast(std.time.nanoTimestamp()),
            .window_score = @floatCast(window_score),
            .mahal_score = @floatCast(mahal_score),
            .digraph_score = @floatCast(digraph_score),
            .confidence = confidence,
            .segment_id = seg,
        };
        const payload = score_msg.toBytes();
        ipc.sendFrame(efd, .score, &payload) catch {
            logErr("enforcer connection lost\n", .{});
            ipc.close(efd);
            enforcer_fd.* = null;
        };
    }
}

fn handleCtlRequest(
    payload: []const u8,
    mode: *Mode,
    enrollment: *EnrollmentState,
    profile: *profile_mod.Profile,
    window: *EventWindow,
    ctl_fd: posix.socket_t,
    config: Config,
) void {
    if (payload.len < 1) return;

    const cmd = std.meta.intToEnum(protocol.CtlCommand, payload[0]) catch return;

    switch (cmd) {
        .enroll_start => {
            if (mode.* == .idle or mode.* == .ready) {
                mode.* = .enrolling;
                enrollment.* = EnrollmentState{};
                enrollment.start_time = std.time.timestamp();
                window.clear();
                logErr("enrollment started\n", .{});
                sendCtlResponse(ctl_fd, 0, "enrollment started");
            } else {
                sendCtlResponse(ctl_fd, 1, "already enrolling or verifying");
            }
        },
        .enroll_status => {
            var buf: [256]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "mode={s} events={d} windows={d}", .{
                @tagName(mode.*),
                enrollment.total_events,
                enrollment.windows_processed,
            }) catch return;
            sendCtlResponse(ctl_fd, 0, msg);
        },
        .enroll_activate => {
            if (mode.* != .enrolling) {
                sendCtlResponse(ctl_fd, 1, "not in enrollment mode");
                return;
            }
            // Finalize enrollment: build profile from Welford accumulators
            finalizeEnrollment(enrollment, profile);
            mode.* = .verifying;
            logErr("enrollment finalized, entering verification mode\n", .{});
            sendCtlResponse(ctl_fd, 0, "verification active");
        },
        .enroll_reset => {
            mode.* = .idle;
            enrollment.* = EnrollmentState{};
            profile.* = profile_mod.Profile{};
            window.clear();
            logErr("enrollment reset\n", .{});
            sendCtlResponse(ctl_fd, 0, "reset complete");
        },
        .query_status => {
            var status = protocol.StatusPayload{
                .mode = switch (mode.*) {
                    .idle => .idle,
                    .enrolling => .enrolling,
                    .ready => .ready,
                    .verifying => .verifying,
                },
                .score = 0,
                .confidence = 0,
                .event_count = 0,
                .segment_id = 0,
            };
            _ = config;
            const payload_bytes = status.toBytes();
            ipc.sendFrame(ctl_fd, .status, &payload_bytes) catch {};
        },
        .manual_lock, .manual_unlock => {
            sendCtlResponse(ctl_fd, 1, "not implemented in analyzer");
        },
    }
}

fn finalizeEnrollment(enrollment: *EnrollmentState, profile: *profile_mod.Profile) void {
    profile.* = profile_mod.Profile{};
    profile.uid = linux.getuid();
    profile.enrollment_start = enrollment.start_time;
    profile.enrollment_end = std.time.timestamp();
    profile.total_events = enrollment.total_events;

    for (0..4) |seg| {
        var mu: [N]f64 = undefined;
        var sigma: [N][N]f64 = undefined;
        enrollment.welford[seg].finalize(&mu, &sigma);

        profile.segments[seg].mu = mu;
        profile.segments[seg].sample_count = @intCast(enrollment.welford[seg].count);

        // Compute Cholesky decomposition
        linalg.choleskyDecompose(&sigma, &profile.segments[seg].cholesky_L) catch {
            logErr("WARNING: Cholesky failed for segment {d}, using identity\n", .{seg});
            for (0..N) |i| {
                for (0..N) |j| {
                    profile.segments[seg].cholesky_L[i][j] = if (i == j) 1.0 else 0.0;
                }
            }
        };

        // Per-digraph stats
        for (0..features_mod.num_digraph_features) |d| {
            profile.segments[seg].digraph_stats[d] = .{
                .mean = enrollment.digraph_accums[seg][d].mean(),
                .stddev = enrollment.digraph_accums[seg][d].stddev(),
                .count = enrollment.digraph_accums[seg][d].count,
            };
        }

        // Copy to anchor (frozen)
        profile.anchor_segments[seg] = profile.segments[seg];
    }

    logErr("profile built: {d} segments active\n", .{
        countActiveSegments(profile),
    });
}

fn countActiveSegments(profile: *const profile_mod.Profile) usize {
    var count: usize = 0;
    for (profile.segments) |seg| {
        if (seg.sample_count > 0) count += 1;
    }
    return count;
}

fn sendCtlResponse(fd: posix.socket_t, status: u8, msg: []const u8) void {
    var buf: [256]u8 = undefined;
    if (msg.len + 1 > buf.len) return;
    buf[0] = status;
    @memcpy(buf[1..][0..msg.len], msg);
    ipc.sendFrame(fd, .ctl_response, buf[0 .. msg.len + 1]) catch {};
}

// -- Logging helpers --

fn writeOut(comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;
    _ = std.posix.write(std.posix.STDOUT_FILENO, msg) catch {};
}

fn logErr(comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;
    _ = std.posix.write(std.posix.STDERR_FILENO, msg) catch {};
}
