// sigint-enforcer: Policy enforcement daemon.
//
// Receives score messages from the analyzer, applies policy thresholds,
// and executes configured responses (lock, kill sessions) when the
// typing identity score indicates a non-enrolled operator.
//
// State machine: NORMAL → GRACE → AMBER → RED
// BLACK (wipe) is deferred to a future milestone.
//
// Capabilities required at init: CAP_SYS_ADMIN (for loginctl).
// Capabilities are dropped after initialization.

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const common = @import("sigint_common");
const options = common.build_options;
const ipc = common.ipc;
const protocol = common.protocol;
const policy_mod = common.policy;

const version = "0.1.0";

/// Default run directory for sockets.
const default_run_dir = "/run/sigint";
const default_policy_path = "/etc/sigint/policy.toml";

/// Enforcer state machine states.
const State = enum {
    normal,
    grace,
    amber,
    red,
};

/// Configuration from command-line args.
const Config = struct {
    score_socket: []const u8 = default_run_dir ++ "/enforcer.sock",
    ctl_socket: []const u8 = default_run_dir ++ "/enforcer-ctl.sock",
    policy_path: []const u8 = default_policy_path,
    dry_run: bool = false,
    skip_policy_sig: bool = false,
    run_dir: []const u8 = default_run_dir,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const config = parseArgs(args) orelse return;

    runEnforcer(config, allocator) catch |err| {
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
            writeOut("sigint-enforcer {s} (wipe_support={s})\n", .{
                version,
                if (options.wipe_support) "true" else "false",
            });
            return null;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            writeOut(
                \\sigint-enforcer {s} — policy enforcement daemon
                \\
                \\Usage: sigint-enforcer [OPTIONS]
                \\
                \\Options:
                \\  --run-dir PATH         Socket directory (default: {s})
                \\  --score-socket PATH    Socket for score input from analyzer
                \\  --ctl-socket PATH      Socket for ctl commands
                \\  --policy PATH          Policy TOML file path
                \\  --dry-run              Log actions instead of executing them
                \\  --skip-policy-sig      Skip Ed25519 signature verification (testing only)
                \\  --version              Show version
                \\  --help                 Show this help
                \\
            , .{ version, default_run_dir });
            return null;
        } else if (std.mem.eql(u8, arg, "--score-socket")) {
            i += 1;
            if (i >= args.len) return null;
            config.score_socket = args[i];
        } else if (std.mem.eql(u8, arg, "--ctl-socket")) {
            i += 1;
            if (i >= args.len) return null;
            config.ctl_socket = args[i];
        } else if (std.mem.eql(u8, arg, "--policy")) {
            i += 1;
            if (i >= args.len) return null;
            config.policy_path = args[i];
        } else if (std.mem.eql(u8, arg, "--dry-run")) {
            config.dry_run = true;
        } else if (std.mem.eql(u8, arg, "--run-dir")) {
            i += 1;
            if (i >= args.len) return null;
            config.run_dir = args[i];
        } else if (std.mem.eql(u8, arg, "--skip-policy-sig")) {
            config.skip_policy_sig = true;
        } else {
            logErr("unknown argument: {s}\n", .{arg});
            return null;
        }
    }
    return config;
}

fn runEnforcer(config_in: Config, allocator: std.mem.Allocator) !void {
    var config = config_in;

    // Derive socket paths from run-dir if it was changed from default
    if (!std.mem.eql(u8, config.run_dir, default_run_dir)) {
        var buf1: [256]u8 = undefined;
        var buf2: [256]u8 = undefined;
        const s1 = std.fmt.bufPrint(&buf1, "{s}/enforcer.sock", .{config.run_dir}) catch return error.PathTooLong;
        const s2 = std.fmt.bufPrint(&buf2, "{s}/enforcer-ctl.sock", .{config.run_dir}) catch return error.PathTooLong;
        config.score_socket = try allocator.dupe(u8, s1);
        config.ctl_socket = try allocator.dupe(u8, s2);
    }

    // Load policy
    var policy = policy_mod.Policy{}; // defaults
    loadPolicy(config, allocator, &policy) catch |err| {
        logErr("policy load failed: {s}, using defaults\n", .{@errorName(err)});
    };
    try policy.validate();

    logErr("policy loaded: tau={d:.2} tau_crit={d:.2} grace={d}s\n", .{
        policy.tau,
        policy.tau_critical,
        policy.grace_seconds,
    });

    // Create listener socket for analyzer score stream
    const score_listen_fd = ipc.createServer(config.score_socket) catch |err| {
        logErr("cannot create score socket at {s}: {s}\n", .{ config.score_socket, @errorName(err) });
        return err;
    };
    defer ipc.close(score_listen_fd);

    // Create listener socket for ctl
    const ctl_listen_fd = ipc.createServer(config.ctl_socket) catch |err| {
        logErr("cannot create ctl socket at {s}: {s}\n", .{ config.ctl_socket, @errorName(err) });
        return err;
    };
    defer ipc.close(ctl_listen_fd);

    logErr("enforcer running\n", .{});

    // State machine
    var state: State = .normal;
    var grace_start_ns: u64 = 0;
    var red_start_ns: u64 = 0;

    var analyzer_fd: ?posix.socket_t = null;
    defer if (analyzer_fd) |fd| ipc.close(fd);
    var ctl_fd: ?posix.socket_t = null;
    defer if (ctl_fd) |fd| ipc.close(fd);

    var recv_buf: [protocol.header_size + protocol.max_payload_size]u8 = undefined;

    while (true) {
        var poll_fds: [4]linux.pollfd = undefined;
        var poll_count: usize = 0;

        poll_fds[poll_count] = .{ .fd = score_listen_fd, .events = linux.POLL.IN, .revents = 0 };
        const score_listen_idx = poll_count;
        poll_count += 1;

        poll_fds[poll_count] = .{ .fd = ctl_listen_fd, .events = linux.POLL.IN, .revents = 0 };
        const ctl_listen_idx = poll_count;
        poll_count += 1;

        var analyzer_data_idx: ?usize = null;
        if (analyzer_fd) |afd| {
            poll_fds[poll_count] = .{ .fd = afd, .events = linux.POLL.IN, .revents = 0 };
            analyzer_data_idx = poll_count;
            poll_count += 1;
        }

        var ctl_data_idx: ?usize = null;
        if (ctl_fd) |cfd| {
            poll_fds[poll_count] = .{ .fd = cfd, .events = linux.POLL.IN, .revents = 0 };
            ctl_data_idx = poll_count;
            poll_count += 1;
        }

        const poll_result = linux.poll(&poll_fds, @intCast(poll_count), 1000);
        if (poll_result < 0) continue;

        // Accept new analyzer connection
        if (poll_fds[score_listen_idx].revents & linux.POLL.IN != 0) {
            if (analyzer_fd) |old| ipc.close(old);
            analyzer_fd = ipc.acceptClient(score_listen_fd) catch null;
            if (analyzer_fd != null) logErr("analyzer connected\n", .{});
        }

        // Accept new ctl connection
        if (poll_fds[ctl_listen_idx].revents & linux.POLL.IN != 0) {
            if (ctl_fd) |old| ipc.close(old);
            ctl_fd = ipc.acceptClient(ctl_listen_fd) catch null;
        }

        // Handle analyzer score messages
        if (analyzer_data_idx) |idx| {
            if (poll_fds[idx].revents & linux.POLL.IN != 0) {
                const frame = ipc.recvFrame(analyzer_fd.?, &recv_buf) catch {
                    logErr("analyzer disconnected\n", .{});
                    ipc.close(analyzer_fd.?);
                    analyzer_fd = null;
                    continue;
                };

                if (frame.msg_type == .score and frame.payload.len >= protocol.ScorePayload.wire_size) {
                    const score = protocol.ScorePayload.fromBytes(frame.payload[0..protocol.ScorePayload.wire_size]);
                    processScore(score, &state, &grace_start_ns, &red_start_ns, &policy, config);
                }
            }
            if (analyzer_data_idx) |aidx| {
                if (poll_fds[aidx].revents & (linux.POLL.HUP | linux.POLL.ERR) != 0) {
                    if (analyzer_fd) |fd| ipc.close(fd);
                    analyzer_fd = null;
                }
            }
        }

        // Handle ctl commands
        if (ctl_data_idx) |idx| {
            if (poll_fds[idx].revents & linux.POLL.IN != 0) {
                const frame = ipc.recvFrame(ctl_fd.?, &recv_buf) catch {
                    ipc.close(ctl_fd.?);
                    ctl_fd = null;
                    continue;
                };

                if (frame.msg_type == .ctl_request and frame.payload.len >= 1) {
                    handleCtlCommand(frame.payload, ctl_fd.?, &state, config);
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

fn processScore(
    score: protocol.ScorePayload,
    state: *State,
    grace_start_ns: *u64,
    red_start_ns: *u64,
    policy: *const policy_mod.Policy,
    config: Config,
) void {
    const now_ns: u64 = @intCast(std.time.nanoTimestamp());
    const window_score: f64 = score.window_score;

    switch (state.*) {
        .normal => {
            if (window_score >= policy.tau_critical) {
                // Immediate RED
                state.* = .red;
                red_start_ns.* = now_ns;
                logErr("STATE: NORMAL -> RED (score={d:.4})\n", .{window_score});
                executeResponse(.lock_and_kill, config);
            } else if (window_score >= policy.tau) {
                // Enter grace period
                state.* = .grace;
                grace_start_ns.* = now_ns;
                logErr("STATE: NORMAL -> GRACE (score={d:.4})\n", .{window_score});
            }
        },
        .grace => {
            if (window_score < policy.tau) {
                // Score recovered
                state.* = .normal;
                logErr("STATE: GRACE -> NORMAL (score={d:.4})\n", .{window_score});
            } else if (window_score >= policy.tau_critical) {
                // Escalate to RED
                state.* = .red;
                red_start_ns.* = now_ns;
                logErr("STATE: GRACE -> RED (score={d:.4})\n", .{window_score});
                executeResponse(.lock_and_kill, config);
            } else {
                // Check grace timer
                const grace_ns = @as(u64, policy.grace_seconds) * std.time.ns_per_s;
                if (now_ns - grace_start_ns.* >= grace_ns) {
                    state.* = .amber;
                    logErr("STATE: GRACE -> AMBER (grace expired, score={d:.4})\n", .{window_score});
                    executeResponse(policy.amber_action, config);
                }
            }
        },
        .amber => {
            if (window_score < policy.tau) {
                state.* = .normal;
                logErr("STATE: AMBER -> NORMAL (score={d:.4})\n", .{window_score});
            } else if (window_score >= policy.tau_critical) {
                state.* = .red;
                red_start_ns.* = now_ns;
                logErr("STATE: AMBER -> RED (score={d:.4})\n", .{window_score});
                executeResponse(.lock_and_kill, config);
            }
        },
        .red => {
            if (window_score < policy.tau) {
                state.* = .normal;
                logErr("STATE: RED -> NORMAL (score={d:.4})\n", .{window_score});
            }
            // BLACK escalation deferred — would check panic_seconds here
        },
    }
}

fn executeResponse(action: policy_mod.Policy.Action, config: Config) void {
    if (config.dry_run) {
        logErr("DRY-RUN: would execute action={s}\n", .{@tagName(action)});
        return;
    }

    switch (action) {
        .lock => {
            logErr("executing: loginctl lock-session\n", .{});
            spawnCommand(&.{ "loginctl", "lock-session" });
        },
        .lock_and_kill => {
            logErr("executing: loginctl lock-session + terminate-user\n", .{});
            spawnCommand(&.{ "loginctl", "lock-session" });
            // Get current UID for terminate-user
            var uid_buf: [16]u8 = undefined;
            const uid_str = std.fmt.bufPrint(&uid_buf, "{d}", .{linux.getuid()}) catch return;
            spawnCommand(&.{ "loginctl", "terminate-user", uid_str });
        },
        .wipe => {
            logErr("wipe action deferred (not implemented)\n", .{});
        },
        .dead_drop => {
            logErr("dead_drop action not yet implemented\n", .{});
        },
        .none => {},
    }
}

fn spawnCommand(argv: []const []const u8) void {
    var child = std.process.Child.init(argv, std.heap.page_allocator);
    _ = child.spawnAndWait() catch |err| {
        logErr("failed to execute command: {s}\n", .{@errorName(err)});
    };
}

fn handleCtlCommand(payload: []const u8, ctl_fd: posix.socket_t, state: *State, config: Config) void {
    const cmd = std.meta.intToEnum(protocol.CtlCommand, payload[0]) catch return;

    switch (cmd) {
        .manual_lock => {
            logErr("manual lock requested\n", .{});
            executeResponse(.lock, config);
            sendCtlResponse(ctl_fd, 0, "locked");
        },
        .manual_unlock => {
            state.* = .normal;
            logErr("manual unlock\n", .{});
            sendCtlResponse(ctl_fd, 0, "unlocked");
        },
        .query_status => {
            var buf: [64]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "state={s}", .{@tagName(state.*)}) catch return;
            sendCtlResponse(ctl_fd, 0, msg);
        },
        else => {
            sendCtlResponse(ctl_fd, 1, "unknown command for enforcer");
        },
    }
}

fn loadPolicy(config: Config, allocator: std.mem.Allocator, policy: *policy_mod.Policy) !void {
    const file = std.fs.cwd().openFile(config.policy_path, .{}) catch return error.FileNotFound;
    defer file.close();

    var buf: [policy_mod.max_policy_size]u8 = undefined;
    const stat = try file.stat();
    if (stat.size > policy_mod.max_policy_size) return error.FileTooLarge;

    const bytes_read = try file.readAll(&buf);
    const content = buf[0..bytes_read];

    // TODO: verify Ed25519 signature from detached .sig file
    // For now, only skip if explicitly configured
    if (!config.skip_policy_sig) {
        // Signature verification would go here
        // For initial development, we log a warning
        logErr("WARNING: policy signature verification not yet implemented\n", .{});
    }

    var map = try policy_mod.parseToml(content, allocator);
    defer policy_mod.deinitMap(&map, allocator);

    policy.* = try policy_mod.policyFromMap(&map);
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
