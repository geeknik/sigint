// sigint-collector: Keystroke event collector daemon.
//
// Reads raw evdev events from keyboard input devices, pseudonymizes
// keycodes to key classes, and streams timestamped events to the
// analyzer over a Unix domain socket.
//
// Capabilities required: CAP_DAC_READ_SEARCH (or `input` group membership)
// for reading /dev/input/eventN.

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const common = @import("sigint_common");
const KeyClass = common.key_class.KeyClass;
const evdevToClass = common.key_class.evdevToClass;
const Event = common.event.Event;
const Direction = common.event.Direction;
const InputEvent = common.evdev.InputEvent;
const ipc = common.ipc;
const protocol = common.protocol;

const version = "0.1.0";

/// Default run directory for sockets.
const default_run_dir = "/run/sigint";

/// Maximum number of keyboard devices to monitor simultaneously.
const max_devices = 8;

/// Event batch buffer size — flush when this many events accumulate.
const batch_size: usize = 64;

/// Fallback lock timeout: if enforcer is unreachable for this many nanoseconds,
/// the collector locks the session directly.
const enforcer_death_timeout_ns: u64 = 10 * std.time.ns_per_s;

/// Configuration parsed from command-line arguments.
const Config = struct {
    analyzer_socket: []const u8 = default_run_dir ++ "/collector.sock",
    grab_devices: bool = false,
    device_path: ?[]const u8 = null, // specific device, or null for auto-detect
    dry_run: bool = false, // print events to stderr instead of sending to analyzer
    run_dir: []const u8 = default_run_dir,
    run_dir_set: bool = false,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var config = parseArgs(args) orelse return;

    // If --run-dir was set but --socket was not, derive socket path from run-dir
    if (config.run_dir_set) {
        var path_buf: [256]u8 = undefined;
        const sock_path = std.fmt.bufPrint(&path_buf, "{s}/collector.sock", .{config.run_dir}) catch {
            logErr("--run-dir path too long\n", .{});
            std.process.exit(1);
        };
        // Copy to heap so it outlives this scope
        const duped = allocator.dupe(u8, sock_path) catch {
            logErr("out of memory\n", .{});
            std.process.exit(1);
        };
        config.analyzer_socket = duped;
    }

    run(config) catch |err| {
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
            writeOut("sigint-collector {s}\n", .{version});
            return null;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            writeOut(
                \\sigint-collector {s} — keystroke event collector
                \\
                \\Usage: sigint-collector [OPTIONS]
                \\
                \\Options:
                \\  --run-dir PATH  Socket directory (default: {s})
                \\  --socket PATH   Analyzer socket path (overrides --run-dir)
                \\  --device PATH   Specific input device (default: auto-detect)
                \\  --grab          Obtain exclusive access to input devices (EVIOCGRAB)
                \\  --dry-run       Print events to stderr instead of sending to analyzer
                \\  --version       Show version
                \\  --help          Show this help
                \\
            , .{ version, default_run_dir });
            return null;
        } else if (std.mem.eql(u8, arg, "--run-dir")) {
            i += 1;
            if (i >= args.len) {
                logErr("--run-dir requires an argument\n", .{});
                return null;
            }
            config.run_dir = args[i];
            config.run_dir_set = true;
        } else if (std.mem.eql(u8, arg, "--socket")) {
            i += 1;
            if (i >= args.len) {
                logErr("--socket requires an argument\n", .{});
                return null;
            }
            config.analyzer_socket = args[i];
        } else if (std.mem.eql(u8, arg, "--device")) {
            i += 1;
            if (i >= args.len) {
                logErr("--device requires an argument\n", .{});
                return null;
            }
            config.device_path = args[i];
        } else if (std.mem.eql(u8, arg, "--grab")) {
            config.grab_devices = true;
        } else if (std.mem.eql(u8, arg, "--dry-run")) {
            config.dry_run = true;
        } else {
            logErr("unknown argument: {s}\n", .{arg});
            return null;
        }
    }
    return config;
}

fn run(config: Config) !void {
    // Open input device(s)
    var device_fds: [max_devices]posix.fd_t = undefined;
    var device_count: usize = 0;

    if (config.device_path) |path| {
        // Specific device
        const fd = posix.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0) catch |err| {
            logErr("cannot open {s}: {s}\n", .{ path, @errorName(err) });
            return err;
        };
        if (config.grab_devices) grabDevice(fd, path);
        device_fds[0] = fd;
        device_count = 1;
        logErr("opened device: {s}\n", .{path});
    } else {
        // Auto-detect keyboards
        device_count = try detectKeyboards(&device_fds, config.grab_devices);
        if (device_count == 0) {
            logErr("no keyboard devices found in /dev/input/\n", .{});
            return error.NoDevicesFound;
        }
        logErr("detected {d} keyboard device(s)\n", .{device_count});
    }

    defer {
        for (device_fds[0..device_count]) |fd| {
            posix.close(fd);
        }
    }

    // Connect to analyzer (unless dry-run)
    var analyzer_fd: ?posix.socket_t = null;
    if (!config.dry_run) {
        analyzer_fd = connectWithRetry(config.analyzer_socket);
        if (analyzer_fd == null) {
            logErr("cannot connect to analyzer at {s}, running in dry-run mode\n", .{config.analyzer_socket});
        }
    }
    defer if (analyzer_fd) |fd| ipc.close(fd);

    // Main event loop
    var batch_buf: [batch_size]Event = undefined;
    var batch_count: usize = 0;

    // Frame serialization buffer
    var frame_buf: [protocol.header_size + 2 + batch_size * Event.wire_size]u8 = undefined;
    var event_wire_buf: [2 + batch_size * Event.wire_size]u8 = undefined;

    logErr("collector running\n", .{});

    while (true) {
        // Poll all device fds for readability
        var poll_fds: [max_devices]linux.pollfd = undefined;
        for (device_fds[0..device_count], 0..) |fd, idx| {
            poll_fds[idx] = .{
                .fd = fd,
                .events = linux.POLL.IN,
                .revents = 0,
            };
        }

        const poll_result = linux.poll(&poll_fds, @intCast(device_count), 1000); // 1s timeout
        if (poll_result < 0) continue; // interrupted
        if (poll_result == 0) {
            // Timeout — flush any pending batch
            if (batch_count > 0) {
                flushBatch(batch_buf[0..batch_count], &analyzer_fd, &event_wire_buf, &frame_buf, config);
                batch_count = 0;
            }
            continue;
        }

        for (poll_fds[0..device_count]) |pfd| {
            if (pfd.revents & linux.POLL.IN == 0) continue;

            const raw = common.evdev.readEvent(pfd.fd) catch continue;
            const input_ev = raw orelse continue;

            // Filter: only EV_KEY events, ignore auto-repeat
            if (input_ev.type != common.evdev.EV_KEY) continue;
            if (input_ev.value == common.evdev.KEY_REPEAT) continue;

            // Map keycode to key class
            const key_class = evdevToClass(input_ev.code) orelse continue;

            // Direction
            const direction: Direction = if (input_ev.value == common.evdev.KEY_PRESS) .press else .release;

            // Use monotonic clock for consistent timing
            const timestamp_ns: u64 = @intCast(std.time.nanoTimestamp());

            const event = Event{
                .key_class = key_class,
                .direction = direction,
                .timestamp_ns = timestamp_ns,
            };

            batch_buf[batch_count] = event;
            batch_count += 1;

            if (batch_count >= batch_size) {
                flushBatch(batch_buf[0..batch_count], &analyzer_fd, &event_wire_buf, &frame_buf, config);
                batch_count = 0;
            }
        }
    }
}

fn flushBatch(
    events: []const Event,
    analyzer_fd: *?posix.socket_t,
    event_wire_buf: []u8,
    frame_buf: []u8,
    config: Config,
) void {
    if (events.len == 0) return;

    if (config.dry_run or analyzer_fd.* == null) {
        // Dry-run: print to stderr
        for (events) |ev| {
            logErr("[{d}] {s} {s}\n", .{
                ev.timestamp_ns,
                @tagName(ev.key_class),
                @tagName(ev.direction),
            });
        }
        return;
    }

    // Serialize event batch
    const payload_len = Event.serializeBatch(events, event_wire_buf) catch return;
    const frame_len = protocol.writeFrame(.event_batch, event_wire_buf[0..payload_len], frame_buf) catch return;

    // Send to analyzer
    ipc.sendFrame(analyzer_fd.*.?, .event_batch, event_wire_buf[0..payload_len]) catch {
        // Connection lost — try to reconnect
        logErr("analyzer connection lost, reconnecting...\n", .{});
        ipc.close(analyzer_fd.*.?);
        analyzer_fd.* = connectWithRetry(config.analyzer_socket);
        if (analyzer_fd.* == null) {
            logErr("reconnect failed\n", .{});
        }
        _ = frame_len;
        return;
    };
}

/// Scan /dev/input/event* for keyboard devices by checking EV_KEY capability.
fn detectKeyboards(out_fds: *[max_devices]posix.fd_t, grab: bool) !usize {
    var count: usize = 0;
    var path_buf: [64]u8 = undefined;

    for (0..32) |i| {
        const path = std.fmt.bufPrint(&path_buf, "/dev/input/event{d}", .{i}) catch continue;

        const fd = posix.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0) catch continue;

        // Check if device has EV_KEY capability
        if (hasKeyCapability(fd)) {
            if (grab) grabDevice(fd, path);
            out_fds[count] = fd;
            count += 1;
            logErr("  keyboard: {s}\n", .{path});
            if (count >= max_devices) break;
        } else {
            posix.close(fd);
        }
    }

    return count;
}

/// Check if an input device supports EV_KEY events.
fn hasKeyCapability(fd: posix.fd_t) bool {
    var ev_bits: [8]u8 = [_]u8{0} ** 8; // enough for 64 event types
    const ioctl_cmd = common.evdev.eviocgbit(0, @intCast(ev_bits.len));

    const rc = linux.ioctl(@intCast(fd), ioctl_cmd, @intFromPtr(&ev_bits));
    if (rc != 0) return false;

    // Check if bit 1 (EV_KEY) is set
    return (ev_bits[0] & (1 << common.evdev.EV_KEY)) != 0;
}

/// Attempt EVIOCGRAB for exclusive device access.
fn grabDevice(fd: posix.fd_t, path: []const u8) void {
    var grab_val: c_int = 1;
    const rc = linux.ioctl(@intCast(fd), common.evdev.EVIOCGRAB, @intFromPtr(&grab_val));
    if (rc == 0) {
        logErr("  grabbed exclusive access: {s}\n", .{path});
    } else {
        logErr("  EVIOCGRAB failed for {s} (non-fatal)\n", .{path});
    }
}

/// Connect to analyzer with retry (up to 3 attempts with 1s backoff).
fn connectWithRetry(path: []const u8) ?posix.socket_t {
    for (0..3) |attempt| {
        const fd = ipc.connectToServer(path) catch {
            if (attempt < 2) {
                std.Thread.sleep(1 * std.time.ns_per_s);
            }
            continue;
        };
        return fd;
    }
    return null;
}

/// Execute fallback session lock when enforcer is unreachable.
fn fallbackLock() void {
    logErr("enforcer unreachable, executing fallback lock\n", .{});
    var child = std.process.Child.init(
        &.{ "loginctl", "lock-session" },
        std.heap.page_allocator,
    );
    _ = child.spawnAndWait() catch {};
}

// -- Logging helpers (write directly to fd, no allocator) --

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
