// IPC wire protocol for SIGINT inter-process communication.
//
// All communication between collector, analyzer, enforcer, and ctl uses
// a simple length-prefixed frame format over Unix domain sockets.
//
// Frame format:
//   [magic: 4 bytes "SIGT"][msg_type: u8][payload_len: u16 LE][payload: N bytes]
//
// Maximum payload size: 65535 bytes (u16 max).
// All multi-byte integers are little-endian.

const std = @import("std");

/// Frame header magic bytes.
pub const magic = [4]u8{ 'S', 'I', 'G', 'T' };

/// Maximum payload size (u16 max).
pub const max_payload_size: usize = 65535;

/// Frame header size in bytes.
pub const header_size: usize = 7; // 4 (magic) + 1 (type) + 2 (length)

/// Message types for IPC communication.
pub const MsgType = enum(u8) {
    /// Batch of keystroke events (collector → analyzer).
    event_batch = 0x01,
    /// Scoring result (analyzer → enforcer).
    score = 0x02,
    /// Control request (ctl → analyzer or enforcer).
    ctl_request = 0x03,
    /// Control response (analyzer or enforcer → ctl).
    ctl_response = 0x04,
    /// Status query/response.
    status = 0x05,
};

/// Control commands sent via ctl_request.
pub const CtlCommand = enum(u8) {
    enroll_start = 0x10,
    enroll_status = 0x11,
    enroll_activate = 0x12,
    enroll_reset = 0x13,
    query_status = 0x20,
    manual_lock = 0x30,
    manual_unlock = 0x31,
};

/// Score message payload (analyzer → enforcer).
/// Fixed 24-byte packed format.
pub const ScorePayload = struct {
    timestamp_ns: u64,
    window_score: f32,
    mahal_score: f32,
    digraph_score: f32,
    confidence: f32,
    segment_id: u8,

    pub const wire_size: usize = 25;

    pub fn toBytes(self: ScorePayload) [wire_size]u8 {
        var buf: [wire_size]u8 = undefined;
        std.mem.writeInt(u64, buf[0..8], self.timestamp_ns, .little);
        @memcpy(buf[8..12], &@as([4]u8, @bitCast(self.window_score)));
        @memcpy(buf[12..16], &@as([4]u8, @bitCast(self.mahal_score)));
        @memcpy(buf[16..20], &@as([4]u8, @bitCast(self.digraph_score)));
        @memcpy(buf[20..24], &@as([4]u8, @bitCast(self.confidence)));
        buf[24] = self.segment_id;
        return buf;
    }

    pub fn fromBytes(buf: *const [wire_size]u8) ScorePayload {
        return .{
            .timestamp_ns = std.mem.readInt(u64, buf[0..8], .little),
            .window_score = @bitCast(buf[8..12].*),
            .mahal_score = @bitCast(buf[12..16].*),
            .digraph_score = @bitCast(buf[16..20].*),
            .confidence = @bitCast(buf[20..24].*),
            .segment_id = buf[24],
        };
    }
};

/// Status response payload.
pub const StatusPayload = struct {
    mode: Mode,
    score: f32,
    confidence: f32,
    event_count: u32,
    segment_id: u8,

    pub const Mode = enum(u8) {
        idle = 0,
        enrolling = 1,
        ready = 2,
        verifying = 3,
    };

    pub const wire_size: usize = 14;

    pub fn toBytes(self: StatusPayload) [wire_size]u8 {
        var buf: [wire_size]u8 = undefined;
        buf[0] = @intFromEnum(self.mode);
        @memcpy(buf[1..5], &@as([4]u8, @bitCast(self.score)));
        @memcpy(buf[5..9], &@as([4]u8, @bitCast(self.confidence)));
        std.mem.writeInt(u32, buf[9..13], self.event_count, .little);
        buf[13] = self.segment_id;
        return buf;
    }

    pub fn fromBytes(buf: *const [wire_size]u8) !StatusPayload {
        return .{
            .mode = std.meta.intToEnum(Mode, buf[0]) catch return error.InvalidMode,
            .score = @bitCast(buf[1..5].*),
            .confidence = @bitCast(buf[5..9].*),
            .event_count = std.mem.readInt(u32, buf[9..13], .little),
            .segment_id = buf[13],
        };
    }
};

/// Serialize a frame header + payload into a buffer.
/// Returns total frame size (header + payload).
pub fn writeFrame(msg_type: MsgType, payload: []const u8, out: []u8) error{BufferTooSmall}!usize {
    if (payload.len > max_payload_size) return error.BufferTooSmall;
    const total = header_size + payload.len;
    if (out.len < total) return error.BufferTooSmall;

    // Magic
    @memcpy(out[0..4], &magic);
    // Type
    out[4] = @intFromEnum(msg_type);
    // Length (LE)
    std.mem.writeInt(u16, out[5..7], @intCast(payload.len), .little);
    // Payload
    @memcpy(out[7..][0..payload.len], payload);

    return total;
}

/// Parse error types for frame reading.
pub const FrameError = error{
    InvalidMagic,
    InvalidMsgType,
    PayloadTooLarge,
    BufferTooSmall,
    IncompleteFrame,
};

/// Parse a frame header from a buffer.
/// Returns the message type, payload length, and total frame size.
pub fn parseHeader(buf: []const u8) FrameError!struct { msg_type: MsgType, payload_len: u16, total_size: usize } {
    if (buf.len < header_size) return error.IncompleteFrame;

    // Validate magic
    if (!std.mem.eql(u8, buf[0..4], &magic)) return error.InvalidMagic;

    // Parse type
    const msg_type = std.meta.intToEnum(MsgType, buf[4]) catch return error.InvalidMsgType;

    // Parse length
    const payload_len = std.mem.readInt(u16, buf[5..7], .little);

    return .{
        .msg_type = msg_type,
        .payload_len = payload_len,
        .total_size = header_size + payload_len,
    };
}

// ---- Tests ----

test "frame round-trip" {
    const payload = "hello world";
    var buf: [header_size + 11]u8 = undefined;
    const written = try writeFrame(.ctl_request, payload, &buf);
    try std.testing.expectEqual(header_size + 11, written);

    const header = try parseHeader(&buf);
    try std.testing.expectEqual(MsgType.ctl_request, header.msg_type);
    try std.testing.expectEqual(@as(u16, 11), header.payload_len);
    try std.testing.expect(std.mem.eql(u8, payload, buf[header_size..][0..11]));
}

test "invalid magic rejected" {
    var buf = [_]u8{ 'B', 'A', 'D', '!', 0x01, 0, 0 };
    const result = parseHeader(&buf);
    try std.testing.expectError(error.InvalidMagic, result);
}

test "incomplete header rejected" {
    const buf = [_]u8{ 'S', 'I', 'G' };
    const result = parseHeader(&buf);
    try std.testing.expectError(error.IncompleteFrame, result);
}

test "score payload round-trip" {
    const score = ScorePayload{
        .timestamp_ns = 123456789,
        .window_score = 0.42,
        .mahal_score = 0.35,
        .digraph_score = 0.55,
        .confidence = 0.95,
        .segment_id = 2,
    };
    const bytes = score.toBytes();
    const restored = ScorePayload.fromBytes(&bytes);

    try std.testing.expectEqual(score.timestamp_ns, restored.timestamp_ns);
    try std.testing.expectApproxEqAbs(score.window_score, restored.window_score, 1e-6);
    try std.testing.expectApproxEqAbs(score.mahal_score, restored.mahal_score, 1e-6);
    try std.testing.expectEqual(score.segment_id, restored.segment_id);
}

test "status payload round-trip" {
    const status = StatusPayload{
        .mode = .verifying,
        .score = 0.12,
        .confidence = 0.94,
        .event_count = 182,
        .segment_id = 2,
    };
    const bytes = status.toBytes();
    const restored = try StatusPayload.fromBytes(&bytes);

    try std.testing.expectEqual(status.mode, restored.mode);
    try std.testing.expectApproxEqAbs(status.score, restored.score, 1e-6);
    try std.testing.expectEqual(status.event_count, restored.event_count);
}
