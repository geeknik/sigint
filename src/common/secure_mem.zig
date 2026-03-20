// Secure memory primitives.
//
// Wrappers around mlock, secureZero, and madvise(DONTDUMP) for handling
// sensitive data (profile keys, feature vectors, passphrases). Ensures
// sensitive buffers are pinned in RAM, excluded from core dumps, and
// zeroed on deallocation.

const std = @import("std");
const linux = std.os.linux;

/// Securely zero a mutable buffer using a volatile write that the
/// compiler cannot optimize away.
pub fn secureZero(comptime T: type, buf: []T) void {
    const bytes = std.mem.sliceAsBytes(buf);
    std.crypto.secureZero(u8, bytes);
}

/// Securely zero a fixed-size array.
pub fn secureZeroArray(comptime N: usize, buf: *[N]u8) void {
    std.crypto.secureZero(u8, buf);
}

/// Lock a memory region into RAM, preventing it from being swapped to disk.
/// Requires appropriate rlimits (RLIMIT_MEMLOCK). Returns error on failure.
pub fn mlock(ptr: [*]const u8, len: usize) !void {
    const result = linux.mlock(ptr, len);
    if (result != 0) {
        return error.MlockFailed;
    }
}

/// Unlock a previously locked memory region.
pub fn munlock(ptr: [*]const u8, len: usize) void {
    _ = linux.munlock(ptr, len);
}

/// Mark a memory region as excluded from core dumps.
pub fn dontdump(ptr: [*]u8, len: usize) !void {
    const MADV_DONTDUMP = 16;
    const aligned_ptr: [*]align(std.mem.page_size) u8 = @alignCast(@ptrCast(ptr));
    const result = linux.madvise(aligned_ptr, len, MADV_DONTDUMP);
    if (result != 0) {
        return error.MadviseFailed;
    }
}

/// Allocator wrapper that securely zeros memory on free.
/// Does NOT mlock (caller should mlock specific sensitive buffers).
pub const SecureAllocator = struct {
    backing: std.mem.Allocator,

    pub fn allocator(self: *SecureAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &vtable,
        };
    }

    const vtable = std.mem.Allocator.VTable{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *SecureAllocator = @ptrCast(@alignCast(ctx));
        return self.backing.rawAlloc(len, alignment, ret_addr);
    }

    fn resize(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *SecureAllocator = @ptrCast(@alignCast(ctx));
        if (new_len < buf.len) {
            // Zero the tail being freed
            std.crypto.secureZero(u8, buf[new_len..]);
        }
        return self.backing.rawResize(buf, alignment, new_len, ret_addr);
    }

    fn remap(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *SecureAllocator = @ptrCast(@alignCast(ctx));
        return self.backing.rawRemap(buf, alignment, new_len, ret_addr);
    }

    fn free(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *SecureAllocator = @ptrCast(@alignCast(ctx));
        // Zero before freeing
        std.crypto.secureZero(u8, buf);
        self.backing.rawFree(buf, alignment, ret_addr);
    }
};

test "secureZero clears buffer" {
    var buf = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    secureZero(u8, &buf);
    for (buf) |b| {
        try std.testing.expectEqual(@as(u8, 0), b);
    }
}

test "SecureAllocator zeros on free" {
    const backing = std.heap.page_allocator;
    var secure = SecureAllocator{ .backing = backing };
    const alloc_ = secure.allocator();

    const buf = try alloc_.alloc(u8, 64);
    @memset(buf, 0xFF);
    // After free, the backing allocator reclaims the memory.
    // We can't easily verify zeroing after free (use-after-free),
    // but the code path exercises the secure zero call.
    alloc_.free(buf);
}
