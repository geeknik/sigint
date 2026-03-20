// sigint-ctl: Administrative CLI for SIGINT.
//
// Provides enrollment management, status queries, policy signing,
// key generation, and manual lock/unlock. Communicates with the
// analyzer and enforcer via Unix domain sockets, authenticated
// with SO_PEERCRED.
//
// No special capabilities required. Operations gated by UID match.

const std = @import("std");
const posix = std.posix;
const common = @import("sigint_common");
const ipc = common.ipc;
const protocol = common.protocol;
const crypto_util = common.crypto_util;
const policy_mod = common.policy;

const version = "0.1.0";

const default_run_dir = "/run/sigint";
const default_analyzer_socket = default_run_dir ++ "/analyzer-ctl.sock";
const default_enforcer_socket = default_run_dir ++ "/enforcer-ctl.sock";

const usage =
    \\sigint-ctl {s} — SIGINT administration tool
    \\
    \\Usage: sigint-ctl <command> [options]
    \\
    \\Commands:
    \\  status                   Show current mode, score, and confidence
    \\  enroll start             Begin enrollment period
    \\  enroll status            Show enrollment quality metrics
    \\  enroll activate          Finalize enrollment and enter verification mode
    \\  enroll reset             Wipe profile and restart enrollment
    \\  policy sign              Sign a policy file with Ed25519
    \\  policy verify            Verify policy file signature
    \\  keygen --output PATH     Generate Ed25519 signing keypair
    \\  lock                     Manually lock the session
    \\  unlock                   Manually unlock after verification
    \\
    \\Options:
    \\  --analyzer-socket PATH   Analyzer ctl socket
    \\  --enforcer-socket PATH   Enforcer ctl socket
    \\  --version                Show version
    \\  --help                   Show this help
    \\
;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        writeOut(usage, .{version});
        return;
    }

    const cmd = args[1];

    if (std.mem.eql(u8, cmd, "--version")) {
        writeOut("sigint-ctl {s}\n", .{version});
        return;
    }
    if (std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h")) {
        writeOut(usage, .{version});
        return;
    }

    // Find socket path options
    var analyzer_socket: []const u8 = default_analyzer_socket;
    var enforcer_socket: []const u8 = default_enforcer_socket;
    var i: usize = 2;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--run-dir") and i + 1 < args.len) {
            i += 1;
            const run_dir = args[i];
            var abuf: [256]u8 = undefined;
            var ebuf: [256]u8 = undefined;
            const a = std.fmt.bufPrint(&abuf, "{s}/analyzer-ctl.sock", .{run_dir}) catch continue;
            const e = std.fmt.bufPrint(&ebuf, "{s}/enforcer-ctl.sock", .{run_dir}) catch continue;
            analyzer_socket = allocator.dupe(u8, a) catch continue;
            enforcer_socket = allocator.dupe(u8, e) catch continue;
        } else if (std.mem.eql(u8, args[i], "--analyzer-socket") and i + 1 < args.len) {
            i += 1;
            analyzer_socket = args[i];
        } else if (std.mem.eql(u8, args[i], "--enforcer-socket") and i + 1 < args.len) {
            i += 1;
            enforcer_socket = args[i];
        }
    }

    if (std.mem.eql(u8, cmd, "status")) {
        try cmdStatus(analyzer_socket);
    } else if (std.mem.eql(u8, cmd, "enroll")) {
        if (args.len < 3) {
            writeErr("usage: sigint-ctl enroll <start|status|activate|reset>\n", .{});
            std.process.exit(1);
        }
        try cmdEnroll(args[2], analyzer_socket);
    } else if (std.mem.eql(u8, cmd, "policy")) {
        if (args.len < 3) {
            writeErr("usage: sigint-ctl policy <sign|verify> [options]\n", .{});
            std.process.exit(1);
        }
        try cmdPolicy(args[2], args, allocator);
    } else if (std.mem.eql(u8, cmd, "keygen")) {
        try cmdKeygen(args);
    } else if (std.mem.eql(u8, cmd, "lock")) {
        try cmdLockUnlock(.manual_lock, enforcer_socket);
    } else if (std.mem.eql(u8, cmd, "unlock")) {
        try cmdLockUnlock(.manual_unlock, enforcer_socket);
    } else {
        writeErr("unknown command: {s}\n", .{cmd});
        std.process.exit(1);
    }
}

fn cmdStatus(socket_path: []const u8) !void {
    const fd = ipc.connectToServer(socket_path) catch {
        writeErr("cannot connect to analyzer at {s}\n", .{socket_path});
        std.process.exit(1);
    };
    defer ipc.close(fd);

    // Send status query
    const cmd_byte = [_]u8{@intFromEnum(protocol.CtlCommand.query_status)};
    try ipc.sendFrame(fd, .ctl_request, &cmd_byte);

    // Receive response
    var recv_buf: [1024]u8 = undefined;
    const frame = try ipc.recvFrame(fd, &recv_buf);

    if (frame.msg_type == .status and frame.payload.len >= protocol.StatusPayload.wire_size) {
        const status = protocol.StatusPayload.fromBytes(frame.payload[0..protocol.StatusPayload.wire_size]) catch {
            writeErr("invalid status response\n", .{});
            return;
        };
        writeOut("Mode:       {s}\n", .{@tagName(status.mode)});
        writeOut("Score:      {d:.4}\n", .{status.score});
        writeOut("Confidence: {d:.2}\n", .{status.confidence});
        writeOut("Events:     {d}\n", .{status.event_count});
        writeOut("Segment:    {d}\n", .{status.segment_id});
    } else if (frame.msg_type == .ctl_response and frame.payload.len > 1) {
        writeOut("{s}\n", .{frame.payload[1..]});
    } else {
        writeErr("unexpected response\n", .{});
    }
}

fn cmdEnroll(subcmd: []const u8, socket_path: []const u8) !void {
    const ctl_cmd: protocol.CtlCommand = if (std.mem.eql(u8, subcmd, "start"))
        .enroll_start
    else if (std.mem.eql(u8, subcmd, "status"))
        .enroll_status
    else if (std.mem.eql(u8, subcmd, "activate"))
        .enroll_activate
    else if (std.mem.eql(u8, subcmd, "reset"))
        .enroll_reset
    else {
        writeErr("unknown enroll subcommand: {s}\n", .{subcmd});
        std.process.exit(1);
    };

    const fd = ipc.connectToServer(socket_path) catch {
        writeErr("cannot connect to analyzer at {s}\n", .{socket_path});
        std.process.exit(1);
    };
    defer ipc.close(fd);

    const cmd_byte = [_]u8{@intFromEnum(ctl_cmd)};
    try ipc.sendFrame(fd, .ctl_request, &cmd_byte);

    var recv_buf: [1024]u8 = undefined;
    const frame = try ipc.recvFrame(fd, &recv_buf);

    if (frame.msg_type == .ctl_response and frame.payload.len > 1) {
        const status = frame.payload[0];
        const msg = frame.payload[1..];
        if (status == 0) {
            writeOut("{s}\n", .{msg});
        } else {
            writeErr("error: {s}\n", .{msg});
            std.process.exit(1);
        }
    }
}

fn cmdPolicy(subcmd: []const u8, args: []const []const u8, allocator: std.mem.Allocator) !void {
    if (std.mem.eql(u8, subcmd, "sign")) {
        try cmdPolicySign(args, allocator);
    } else if (std.mem.eql(u8, subcmd, "verify")) {
        try cmdPolicyVerify(args, allocator);
    } else {
        writeErr("unknown policy subcommand: {s}\n", .{subcmd});
        std.process.exit(1);
    }
}

fn cmdPolicySign(args: []const []const u8, allocator: std.mem.Allocator) !void {
    var key_path: ?[]const u8 = null;
    var policy_path: ?[]const u8 = null;

    var i: usize = 3;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--key") and i + 1 < args.len) {
            i += 1;
            key_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--policy") and i + 1 < args.len) {
            i += 1;
            policy_path = args[i];
        }
    }

    if (key_path == null or policy_path == null) {
        writeErr("usage: sigint-ctl policy sign --key <path> --policy <path>\n", .{});
        std.process.exit(1);
    }

    // Read private key (64 bytes raw Ed25519 secret key)
    const key_file = std.fs.cwd().openFile(key_path.?, .{}) catch {
        writeErr("cannot open key file: {s}\n", .{key_path.?});
        std.process.exit(1);
    };
    defer key_file.close();

    var key_bytes: [crypto_util.Ed25519.SecretKey.encoded_length]u8 = undefined;
    const key_read = key_file.readAll(&key_bytes) catch {
        writeErr("cannot read key file\n", .{});
        std.process.exit(1);
    };
    defer crypto_util.secureZero(&key_bytes);

    if (key_read != key_bytes.len) {
        writeErr("invalid key file size (expected {d} bytes, got {d})\n", .{ key_bytes.len, key_read });
        std.process.exit(1);
    }

    // Read policy file
    const policy_content = std.fs.cwd().readFileAlloc(allocator, policy_path.?, policy_mod.max_policy_size) catch {
        writeErr("cannot read policy file: {s}\n", .{policy_path.?});
        std.process.exit(1);
    };
    defer allocator.free(policy_content);

    // Sign
    const secret_key = crypto_util.Ed25519.SecretKey.fromBytes(key_bytes) catch {
        writeErr("invalid secret key\n", .{});
        std.process.exit(1);
    };
    const public_key = crypto_util.Ed25519.PublicKey.fromBytes(secret_key.publicKeyBytes()) catch {
        writeErr("cannot derive public key\n", .{});
        std.process.exit(1);
    };
    const keypair = crypto_util.Ed25519.KeyPair{
        .secret_key = secret_key,
        .public_key = public_key,
    };

    const sig_bytes = crypto_util.sign(policy_content, keypair) catch {
        writeErr("signing failed\n", .{});
        std.process.exit(1);
    };

    // Write signature to .sig file
    var sig_path_buf: [512]u8 = undefined;
    const sig_path = std.fmt.bufPrint(&sig_path_buf, "{s}.sig", .{policy_path.?}) catch {
        writeErr("policy path too long\n", .{});
        std.process.exit(1);
    };

    const sig_file = std.fs.cwd().createFile(sig_path, .{}) catch {
        writeErr("cannot create signature file: {s}\n", .{sig_path});
        std.process.exit(1);
    };
    defer sig_file.close();

    sig_file.writeAll(&sig_bytes) catch {
        writeErr("cannot write signature\n", .{});
        std.process.exit(1);
    };

    writeOut("signed: {s}\n", .{sig_path});
}

fn cmdPolicyVerify(args: []const []const u8, allocator: std.mem.Allocator) !void {
    var policy_path: ?[]const u8 = null;
    var pubkey_path: ?[]const u8 = null;

    var i: usize = 3;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--policy") and i + 1 < args.len) {
            i += 1;
            policy_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--pubkey") and i + 1 < args.len) {
            i += 1;
            pubkey_path = args[i];
        }
    }

    if (policy_path == null or pubkey_path == null) {
        writeErr("usage: sigint-ctl policy verify --policy <path> --pubkey <path>\n", .{});
        std.process.exit(1);
    }

    // Read public key (32 bytes)
    const pk_file = std.fs.cwd().openFile(pubkey_path.?, .{}) catch {
        writeErr("cannot open public key: {s}\n", .{pubkey_path.?});
        std.process.exit(1);
    };
    defer pk_file.close();

    var pk_bytes: [crypto_util.Ed25519.PublicKey.encoded_length]u8 = undefined;
    const pk_read = pk_file.readAll(&pk_bytes) catch {
        writeErr("cannot read public key\n", .{});
        std.process.exit(1);
    };
    if (pk_read != pk_bytes.len) {
        writeErr("invalid public key size\n", .{});
        std.process.exit(1);
    }

    // Read policy
    const policy_content = std.fs.cwd().readFileAlloc(allocator, policy_path.?, policy_mod.max_policy_size) catch {
        writeErr("cannot read policy file\n", .{});
        std.process.exit(1);
    };
    defer allocator.free(policy_content);

    // Read signature
    var sig_path_buf: [512]u8 = undefined;
    const sig_path = std.fmt.bufPrint(&sig_path_buf, "{s}.sig", .{policy_path.?}) catch {
        writeErr("policy path too long\n", .{});
        std.process.exit(1);
    };

    const sig_file = std.fs.cwd().openFile(sig_path, .{}) catch {
        writeErr("cannot open signature file: {s}\n", .{sig_path});
        std.process.exit(1);
    };
    defer sig_file.close();

    var sig_bytes: [crypto_util.Ed25519.Signature.encoded_length]u8 = undefined;
    const sig_read = sig_file.readAll(&sig_bytes) catch {
        writeErr("cannot read signature\n", .{});
        std.process.exit(1);
    };
    if (sig_read != sig_bytes.len) {
        writeErr("invalid signature size\n", .{});
        std.process.exit(1);
    }

    // Verify
    crypto_util.verify(policy_content, &sig_bytes, &pk_bytes) catch {
        writeErr("FAILED: signature verification failed\n", .{});
        std.process.exit(1);
    };

    writeOut("OK: signature valid\n", .{});
}

fn cmdKeygen(args: []const []const u8) !void {
    var output_path: ?[]const u8 = null;

    var i: usize = 2;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--output") and i + 1 < args.len) {
            i += 1;
            output_path = args[i];
        }
    }

    if (output_path == null) {
        writeErr("usage: sigint-ctl keygen --output <path>\n", .{});
        std.process.exit(1);
    }

    const keypair = crypto_util.generateSigningKeypair();

    // Write secret key
    const sk_file = std.fs.cwd().createFile(output_path.?, .{ .mode = 0o600 }) catch {
        writeErr("cannot create key file: {s}\n", .{output_path.?});
        std.process.exit(1);
    };
    defer sk_file.close();
    sk_file.writeAll(&keypair.secret_key.bytes) catch {
        writeErr("cannot write secret key\n", .{});
        std.process.exit(1);
    };

    // Write public key
    var pub_path_buf: [512]u8 = undefined;
    const pub_path = std.fmt.bufPrint(&pub_path_buf, "{s}.pub", .{output_path.?}) catch {
        writeErr("output path too long\n", .{});
        std.process.exit(1);
    };

    const pk_file = std.fs.cwd().createFile(pub_path, .{}) catch {
        writeErr("cannot create public key file: {s}\n", .{pub_path});
        std.process.exit(1);
    };
    defer pk_file.close();
    pk_file.writeAll(&keypair.public_key.toBytes()) catch {
        writeErr("cannot write public key\n", .{});
        std.process.exit(1);
    };

    writeOut("keypair generated:\n  private: {s}\n  public:  {s}\n", .{ output_path.?, pub_path });
    writeOut("IMPORTANT: store the private key offline after signing.\n", .{});
}

fn cmdLockUnlock(cmd: protocol.CtlCommand, socket_path: []const u8) !void {
    const fd = ipc.connectToServer(socket_path) catch {
        writeErr("cannot connect to enforcer at {s}\n", .{socket_path});
        std.process.exit(1);
    };
    defer ipc.close(fd);

    const cmd_byte = [_]u8{@intFromEnum(cmd)};
    try ipc.sendFrame(fd, .ctl_request, &cmd_byte);

    var recv_buf: [256]u8 = undefined;
    const frame = try ipc.recvFrame(fd, &recv_buf);

    if (frame.msg_type == .ctl_response and frame.payload.len > 1) {
        const status = frame.payload[0];
        const msg = frame.payload[1..];
        if (status == 0) {
            writeOut("{s}\n", .{msg});
        } else {
            writeErr("error: {s}\n", .{msg});
            std.process.exit(1);
        }
    }
}

// -- Output helpers --

fn writeOut(comptime fmt: []const u8, args: anytype) void {
    var buf: [2048]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;
    _ = std.posix.write(std.posix.STDOUT_FILENO, msg) catch {};
}

fn writeErr(comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;
    _ = std.posix.write(std.posix.STDERR_FILENO, msg) catch {};
}
