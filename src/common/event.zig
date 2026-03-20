// Event tuple — the fundamental unit of IPC between collector and analyzer.
//
// Each event represents a single key press or release, pseudonymized to a
// KeyClass (no actual character identity), with a monotonic nanosecond timestamp.

const std = @import("std");
const KeyClass = @import("key_class.zig").KeyClass;

/// Direction of a key event.
pub const Direction = enum(u1) {
    press = 0,
    release = 1,
};

/// A single pseudonymized keystroke event.
/// Wire format: 10 bytes (key_class:1, direction_and_pad:1, timestamp_ns:8).
pub const Event = struct {
    key_class: KeyClass,
    direction: Direction,
    timestamp_ns: u64,

    /// Maximum batch size for IPC transmission.
    pub const max_batch_size: u16 = 256;

    /// Wire size in bytes.
    pub const wire_size: usize = 10;

    /// Serialize to wire format (little-endian).
    pub fn toBytes(self: Event) [wire_size]u8 {
        var buf: [wire_size]u8 = undefined;
        buf[0] = @intFromEnum(self.key_class);
        buf[1] = @intFromEnum(self.direction);
        std.mem.writeInt(u64, buf[2..10], self.timestamp_ns, .little);
        return buf;
    }

    /// Deserialize from wire format.
    pub fn fromBytes(buf: *const [wire_size]u8) error{InvalidKeyClass}!Event {
        const kc_byte = buf[0];
        const dir_byte = buf[1];

        const key_class = std.meta.intToEnum(KeyClass, kc_byte) catch return error.InvalidKeyClass;
        const direction: Direction = if (dir_byte == 0) .press else .release;
        const timestamp_ns = std.mem.readInt(u64, buf[2..10], .little);

        return Event{
            .key_class = key_class,
            .direction = direction,
            .timestamp_ns = timestamp_ns,
        };
    }

    /// Serialize a batch of events into a buffer.
    /// Format: [count:u16 LE][Event * count]
    /// Returns the number of bytes written.
    pub fn serializeBatch(events: []const Event, out: []u8) error{BufferTooSmall}!usize {
        const count: u16 = std.math.cast(u16, events.len) orelse return error.BufferTooSmall;
        const needed = 2 + events.len * wire_size;
        if (out.len < needed) return error.BufferTooSmall;

        std.mem.writeInt(u16, out[0..2], count, .little);
        for (events, 0..) |ev, i| {
            const offset = 2 + i * wire_size;
            out[offset..][0..wire_size].* = ev.toBytes();
        }
        return needed;
    }

    /// Deserialize a batch from a buffer.
    /// Returns slice of events and the number of bytes consumed.
    pub fn deserializeBatch(buf: []const u8, out: []Event) error{ BufferTooSmall, InvalidKeyClass }!struct { count: usize, bytes_consumed: usize } {
        if (buf.len < 2) return error.BufferTooSmall;

        const count = std.mem.readInt(u16, buf[0..2], .little);
        const needed = 2 + @as(usize, count) * wire_size;
        if (buf.len < needed) return error.BufferTooSmall;
        if (out.len < count) return error.BufferTooSmall;

        for (0..count) |i| {
            const offset = 2 + i * wire_size;
            out[i] = try fromBytes(buf[offset..][0..wire_size]);
        }
        return .{ .count = count, .bytes_consumed = needed };
    }
};

test "event round-trip serialization" {
    const ev = Event{
        .key_class = .home_l,
        .direction = .press,
        .timestamp_ns = 123456789,
    };
    const bytes = ev.toBytes();
    const restored = try Event.fromBytes(&bytes);
    const testing = std.testing;
    try testing.expectEqual(ev.key_class, restored.key_class);
    try testing.expectEqual(ev.direction, restored.direction);
    try testing.expectEqual(ev.timestamp_ns, restored.timestamp_ns);
}

test "event release direction" {
    const ev = Event{
        .key_class = .space,
        .direction = .release,
        .timestamp_ns = 999,
    };
    const bytes = ev.toBytes();
    const restored = try Event.fromBytes(&bytes);
    try std.testing.expectEqual(Direction.release, restored.direction);
}

test "batch round-trip" {
    const events = [_]Event{
        .{ .key_class = .home_l, .direction = .press, .timestamp_ns = 100 },
        .{ .key_class = .home_r, .direction = .press, .timestamp_ns = 200 },
        .{ .key_class = .home_l, .direction = .release, .timestamp_ns = 180 },
    };
    var buf: [2 + 3 * Event.wire_size]u8 = undefined;
    const written = try Event.serializeBatch(&events, &buf);
    try std.testing.expectEqual(2 + 3 * Event.wire_size, written);

    var out: [3]Event = undefined;
    const result = try Event.deserializeBatch(buf[0..written], &out);
    try std.testing.expectEqual(@as(usize, 3), result.count);
    try std.testing.expectEqual(events[0].key_class, out[0].key_class);
    try std.testing.expectEqual(events[1].timestamp_ns, out[1].timestamp_ns);
    try std.testing.expectEqual(events[2].direction, out[2].direction);
}

test "invalid key class byte rejected" {
    var bytes = [_]u8{ 255, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    const result = Event.fromBytes(&bytes);
    try std.testing.expectError(error.InvalidKeyClass, result);
}
