// SIGINT common library — shared across all binaries.
//
// Re-exports all common modules. Each module is independently importable
// via @import("sigint_common").module_name.

pub const build_options = @import("build_options");
pub const key_class = @import("key_class.zig");
pub const event = @import("event.zig");
pub const evdev = @import("evdev.zig");
pub const time_segment = @import("time_segment.zig");
pub const secure_mem = @import("secure_mem.zig");
pub const features = @import("features.zig");
pub const math_linalg = @import("math_linalg.zig");
pub const scoring = @import("scoring.zig");
pub const protocol = @import("protocol.zig");
pub const ipc = @import("ipc.zig");
pub const policy = @import("policy.zig");
pub const crypto_util = @import("crypto_util.zig");
pub const profile = @import("profile.zig");
pub const sandbox = @import("sandbox.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
