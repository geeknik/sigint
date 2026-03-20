// Unix domain socket IPC layer with SO_PEERCRED authentication.
//
// Provides server (listen/accept) and client (connect) abstractions
// over Unix stream sockets. All connections are authenticated via
// SO_PEERCRED to verify the peer's UID before processing messages.

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const protocol = @import("protocol.zig");

/// Peer credentials obtained via SO_PEERCRED.
pub const PeerCred = struct {
    pid: i32,
    uid: u32,
    gid: u32,
};

/// Get peer credentials for a connected Unix socket.
pub fn getPeerCred(fd: posix.socket_t) !PeerCred {
    const SOL_SOCKET = 1;
    const SO_PEERCRED = 17;

    var cred: extern struct {
        pid: i32,
        uid: u32,
        gid: u32,
    } = undefined;

    var len: u32 = @sizeOf(@TypeOf(cred));

    const rc = linux.getsockopt(
        @intCast(fd),
        SOL_SOCKET,
        SO_PEERCRED,
        @ptrCast(&cred),
        &len,
    );

    if (rc != 0) return error.GetSockOptFailed;

    return .{
        .pid = cred.pid,
        .uid = cred.uid,
        .gid = cred.gid,
    };
}

/// Create and bind a Unix stream socket at the given path.
/// Creates parent directories if they don't exist.
/// Returns the listening socket fd.
pub fn createServer(path: []const u8) !posix.socket_t {
    // Ensure parent directory exists
    if (std.fs.path.dirname(path)) |dir| {
        std.fs.cwd().makePath(dir) catch {};
    }

    const sock = try posix.socket(
        posix.AF.UNIX,
        posix.SOCK.STREAM | posix.SOCK.CLOEXEC,
        0,
    );
    errdefer posix.close(sock);

    // Remove existing socket file if present
    std.fs.cwd().deleteFile(path) catch {};

    var addr = std.net.Address.initUnix(path) catch return error.PathTooLong;
    try posix.bind(sock, &addr.any, addr.getOsSockLen());

    // Restrict socket permissions: owner read/write only (0o600)
    const rc = linux.fchmodat(linux.AT.FDCWD, @ptrCast(path.ptr), 0o600, 0);
    _ = rc;

    try posix.listen(sock, 5);

    return sock;
}

/// Accept a connection on a listening Unix socket.
/// Returns the connected client fd.
pub fn acceptClient(listen_fd: posix.socket_t) !posix.socket_t {
    const fd = try posix.accept(listen_fd, null, null, posix.SOCK.CLOEXEC);
    return fd;
}

/// Connect to a Unix domain socket server.
pub fn connectToServer(path: []const u8) !posix.socket_t {
    const sock = try posix.socket(
        posix.AF.UNIX,
        posix.SOCK.STREAM | posix.SOCK.CLOEXEC,
        0,
    );
    errdefer posix.close(sock);

    var addr = std.net.Address.initUnix(path) catch return error.PathTooLong;
    try posix.connect(sock, &addr.any, addr.getOsSockLen());

    return sock;
}

/// Send a complete frame over a socket.
pub fn sendFrame(fd: posix.socket_t, msg_type: protocol.MsgType, payload: []const u8) !void {
    var buf: [protocol.header_size + protocol.max_payload_size]u8 = undefined;
    const frame_len = try protocol.writeFrame(msg_type, payload, &buf);
    _ = try sendAll(fd, buf[0..frame_len]);
}

/// Receive a complete frame from a socket.
/// Returns message type and payload slice within the provided buffer.
pub fn recvFrame(fd: posix.socket_t, buf: []u8) !struct { msg_type: protocol.MsgType, payload: []const u8 } {
    if (buf.len < protocol.header_size) return error.BufferTooSmall;

    // Read header
    try recvExact(fd, buf[0..protocol.header_size]);

    const header = protocol.parseHeader(buf[0..protocol.header_size]) catch |e| switch (e) {
        error.InvalidMagic => return error.InvalidMagic,
        error.InvalidMsgType => return error.InvalidMsgType,
        error.PayloadTooLarge => return error.PayloadTooLarge,
        error.IncompleteFrame => return error.IncompleteFrame,
        error.BufferTooSmall => return error.BufferTooSmall,
    };

    if (header.payload_len > 0) {
        const payload_end = protocol.header_size + header.payload_len;
        if (buf.len < payload_end) return error.BufferTooSmall;
        try recvExact(fd, buf[protocol.header_size..payload_end]);
        return .{
            .msg_type = header.msg_type,
            .payload = buf[protocol.header_size..payload_end],
        };
    }

    return .{
        .msg_type = header.msg_type,
        .payload = &.{},
    };
}

/// Send all bytes (handles partial writes).
fn sendAll(fd: posix.socket_t, data: []const u8) !void {
    var sent: usize = 0;
    while (sent < data.len) {
        const n = posix.write(fd, data[sent..]) catch |e| switch (e) {
            error.WouldBlock => continue,
            else => return e,
        };
        if (n == 0) return error.ConnectionClosed;
        sent += n;
    }
}

/// Receive exactly `buf.len` bytes (handles partial reads).
fn recvExact(fd: posix.socket_t, buf: []u8) !void {
    var received: usize = 0;
    while (received < buf.len) {
        const n = posix.read(fd, buf[received..]) catch |e| switch (e) {
            error.WouldBlock => continue,
            else => return e,
        };
        if (n == 0) return error.ConnectionClosed;
        received += n;
    }
}

/// Close a socket.
pub fn close(fd: posix.socket_t) void {
    posix.close(fd);
}

// ---- Tests ----

test "createServer and connectToServer round-trip" {
    const path = "/tmp/sigint-test-ipc.sock";
    defer std.fs.cwd().deleteFile(path) catch {};

    const server_fd = try createServer(path);
    defer close(server_fd);

    // Connect in this thread (blocking)
    const client_fd = try connectToServer(path);
    defer close(client_fd);

    // Accept on the server side
    const accepted_fd = try acceptClient(server_fd);
    defer close(accepted_fd);

    // Send a frame from client, receive on server
    const payload = "test payload";
    try sendFrame(client_fd, .ctl_request, payload);

    var recv_buf: [256]u8 = undefined;
    const frame = try recvFrame(accepted_fd, &recv_buf);
    try std.testing.expectEqual(protocol.MsgType.ctl_request, frame.msg_type);
    try std.testing.expect(std.mem.eql(u8, payload, frame.payload));
}

test "SO_PEERCRED returns valid uid" {
    const path = "/tmp/sigint-test-peercred.sock";
    defer std.fs.cwd().deleteFile(path) catch {};

    const server_fd = try createServer(path);
    defer close(server_fd);

    const client_fd = try connectToServer(path);
    defer close(client_fd);

    const accepted_fd = try acceptClient(server_fd);
    defer close(accepted_fd);

    const cred = try getPeerCred(accepted_fd);
    // UID should match our current UID
    const our_uid = linux.getuid();
    try std.testing.expectEqual(our_uid, cred.uid);
    // PID should be positive
    try std.testing.expect(cred.pid > 0);
}
