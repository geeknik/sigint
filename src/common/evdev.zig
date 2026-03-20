// Linux evdev interface definitions.
//
// Defines the kernel input_event struct layout and ioctl constants
// needed to read raw keystroke events from /dev/input/eventN.

const std = @import("std");

/// Kernel input_event struct (from linux/input.h).
/// On x86_64: timeval is two i64 (tv_sec, tv_usec), then u16 type, u16 code, i32 value.
/// Total: 24 bytes.
pub const InputEvent = extern struct {
    tv_sec: i64,
    tv_usec: i64,
    type: u16,
    code: u16,
    value: i32,

    pub const size: usize = 24;

    comptime {
        if (@sizeOf(InputEvent) != size) {
            @compileError("InputEvent size mismatch — check platform alignment");
        }
    }

    /// Convert kernel timestamp to monotonic nanoseconds.
    /// Note: evdev timestamps use CLOCK_REALTIME by default. For monotonic
    /// time, we use CLOCK_MONOTONIC via clock_gettime at event receipt.
    pub fn kernelTimestampNs(self: InputEvent) u64 {
        const sec: u64 = @intCast(self.tv_sec);
        const usec: u64 = @intCast(self.tv_usec);
        return sec * std.time.ns_per_s + usec * std.time.ns_per_us;
    }
};

// Event types
pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;

// Key event values
pub const KEY_RELEASE: i32 = 0;
pub const KEY_PRESS: i32 = 1;
pub const KEY_REPEAT: i32 = 2; // auto-repeat — ignored by SIGINT

// EVIOCGRAB ioctl for exclusive device access.
// _IOW('E', 0x90, int) = direction(1) | size(sizeof(int)) | type('E') | nr(0x90)
// On Linux x86_64: _IOW = 0x40000000 | (4 << 16) | ('E' << 8) | 0x90
pub const EVIOCGRAB: u32 = 0x40044590;

// EVIOCGBIT ioctl to query device capabilities.
// _IOC(_IOC_READ, 'E', 0x20 + ev_type, len)
pub fn eviocgbit(ev_type: u8, len: u14) u32 {
    // _IOC_READ = 2, so direction bits = 0x80000000
    const dir: u32 = 0x80000000;
    const size_bits: u32 = @as(u32, len) << 16;
    const type_bits: u32 = @as(u32, 'E') << 8;
    const nr: u32 = 0x20 + @as(u32, ev_type);
    return dir | size_bits | type_bits | nr;
}

/// Read a single InputEvent from a file descriptor.
/// Returns null on EOF or partial read (should not happen with evdev).
pub fn readEvent(fd: std.posix.fd_t) !?InputEvent {
    var ev: InputEvent = undefined;
    const bytes = std.mem.asBytes(&ev);
    const n = try std.posix.read(fd, bytes);
    if (n != InputEvent.size) return null;
    return ev;
}

test "InputEvent is 24 bytes" {
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(InputEvent));
}

test "EVIOCGRAB constant matches expected value" {
    // Verified against linux/input.h: _IOW('E', 0x90, int)
    try std.testing.expectEqual(@as(u32, 0x40044590), EVIOCGRAB);
}
