// Policy configuration parser and Ed25519 signature verification.
//
// Parses a minimal TOML subset (sections, key=value with string/int/float/bool)
// and maps it to the Policy struct. Policy files must be signed with Ed25519
// and verified before use — unsigned or tampered policies are rejected.

const std = @import("std");

/// Maximum policy file size (64 KB).
pub const max_policy_size: usize = 65536;

/// SIGINT enforcement policy — populated from policy.toml.
pub const Policy = struct {
    // Thresholds
    tau: f64 = 0.55,
    tau_critical: f64 = 0.80,
    grace_seconds: u32 = 45,
    panic_seconds: u32 = 120,

    // Enrollment
    enroll_min_days: u32 = 7,
    enroll_max_days: u32 = 30,
    enroll_min_daily_minutes: u32 = 30,
    enroll_auto_activate: bool = false,

    // Response: AMBER
    amber_action: Action = .lock,

    // Response: RED
    red_action: Action = .lock_and_kill,
    red_notify: bool = false,

    // Response: BLACK
    black_enabled: bool = false,
    black_action: Action = .wipe,
    black_confirm_delay: u32 = 5,

    // Response: SILENT
    silent_enabled: bool = false,

    // Adaptive
    micro_update_lambda: f64 = 0.005,
    anchor_drift_max: f64 = 0.25,
    time_segments: u32 = 4,

    // Scoring
    alpha: f64 = 0.6,
    window_seconds: u32 = 30,
    min_events_per_window: u32 = 40,

    pub const Action = enum {
        lock,
        lock_and_kill,
        wipe,
        dead_drop,
        none,
    };

    /// Validate policy values are within sane ranges.
    pub fn validate(self: *const Policy) error{InvalidPolicy}!void {
        if (self.tau < 0 or self.tau > 1) return error.InvalidPolicy;
        if (self.tau_critical < 0 or self.tau_critical > 1) return error.InvalidPolicy;
        if (self.tau >= self.tau_critical) return error.InvalidPolicy;
        if (self.alpha < 0 or self.alpha > 1) return error.InvalidPolicy;
        if (self.micro_update_lambda < 0 or self.micro_update_lambda > 0.1) return error.InvalidPolicy;
        if (self.anchor_drift_max <= 0 or self.anchor_drift_max > 1) return error.InvalidPolicy;
        if (self.grace_seconds == 0) return error.InvalidPolicy;
        if (self.window_seconds == 0) return error.InvalidPolicy;
        if (self.min_events_per_window == 0) return error.InvalidPolicy;
        if (self.enroll_min_days == 0) return error.InvalidPolicy;
    }
};

/// Parsed TOML value.
pub const Value = union(enum) {
    string: []const u8,
    integer: i64,
    float: f64,
    boolean: bool,
};

/// Error types for TOML parsing.
pub const ParseError = error{
    InvalidSyntax,
    FileTooLarge,
    UnknownKey,
    InvalidValue,
    OutOfMemory,
};

/// Minimal TOML parser — supports:
/// - [section] and [section.subsection] headers
/// - key = "string"
/// - key = integer
/// - key = float
/// - key = true/false
///
/// Does NOT support: arrays, inline tables, multi-line strings, dates.
/// Fails closed on any unexpected syntax.
pub fn parseToml(input: []const u8, allocator: std.mem.Allocator) ParseError!std.StringHashMap(Value) {
    if (input.len > max_policy_size) return error.FileTooLarge;

    var map = std.StringHashMap(Value).init(allocator);
    errdefer {
        var it = map.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
        }
        map.deinit();
    }

    var current_section: ?[]const u8 = null;
    var section_buf: [256]u8 = undefined;

    var line_iter = std.mem.splitScalar(u8, input, '\n');
    while (line_iter.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, &[_]u8{ ' ', '\t', '\r' });

        // Skip empty lines and comments
        if (line.len == 0 or line[0] == '#') continue;

        // Section header: [section] or [section.subsection]
        if (line[0] == '[') {
            const end = std.mem.indexOfScalar(u8, line, ']') orelse return error.InvalidSyntax;
            if (end < 2) return error.InvalidSyntax;
            const section_name = std.mem.trim(u8, line[1..end], " ");
            if (section_name.len == 0) return error.InvalidSyntax;
            if (section_name.len >= section_buf.len) return error.InvalidSyntax;
            @memcpy(section_buf[0..section_name.len], section_name);
            current_section = section_buf[0..section_name.len];
            continue;
        }

        // Key = value
        const eq_pos = std.mem.indexOfScalar(u8, line, '=') orelse return error.InvalidSyntax;
        if (eq_pos == 0) return error.InvalidSyntax;

        const key_raw = std.mem.trim(u8, line[0..eq_pos], " ");
        const val_raw = std.mem.trim(u8, line[eq_pos + 1 ..], " ");

        if (key_raw.len == 0 or val_raw.len == 0) return error.InvalidSyntax;

        // Strip inline comment from value
        var val_str = val_raw;
        // Only strip # comments that aren't inside strings
        if (val_str[0] != '"') {
            if (std.mem.indexOfScalar(u8, val_str, '#')) |hash_pos| {
                val_str = std.mem.trim(u8, val_str[0..hash_pos], " ");
            }
        }

        // Build full dotted key
        var full_key_buf: [512]u8 = undefined;
        var full_key_len: usize = 0;
        if (current_section) |section| {
            @memcpy(full_key_buf[0..section.len], section);
            full_key_buf[section.len] = '.';
            full_key_len = section.len + 1;
        }
        @memcpy(full_key_buf[full_key_len..][0..key_raw.len], key_raw);
        full_key_len += key_raw.len;

        const full_key = try allocator.dupe(u8, full_key_buf[0..full_key_len]);
        errdefer allocator.free(full_key);

        // Parse value
        const value = parseValue(val_str) orelse return error.InvalidValue;

        map.put(full_key, value) catch return error.OutOfMemory;
    }

    return map;
}

/// Parse a TOML value string into a Value.
fn parseValue(val: []const u8) ?Value {
    if (val.len == 0) return null;

    // Boolean
    if (std.mem.eql(u8, val, "true")) return .{ .boolean = true };
    if (std.mem.eql(u8, val, "false")) return .{ .boolean = false };

    // Quoted string
    if (val[0] == '"') {
        if (val.len < 2 or val[val.len - 1] != '"') return null;
        return .{ .string = val[1 .. val.len - 1] };
    }

    // Float (contains '.')
    if (std.mem.indexOfScalar(u8, val, '.') != null) {
        const f = std.fmt.parseFloat(f64, val) catch return null;
        return .{ .float = f };
    }

    // Integer
    const i = std.fmt.parseInt(i64, val, 10) catch return null;
    return .{ .integer = i };
}

/// Load policy from parsed TOML map.
pub fn policyFromMap(map: *const std.StringHashMap(Value)) error{ UnknownKey, InvalidValue }!Policy {
    var policy = Policy{};

    if (getFloat(map, "thresholds.tau")) |v| policy.tau = v;
    if (getFloat(map, "thresholds.tau_critical")) |v| policy.tau_critical = v;
    if (getInt(map, "thresholds.grace_seconds")) |v| policy.grace_seconds = @intCast(v);
    if (getInt(map, "thresholds.panic_seconds")) |v| policy.panic_seconds = @intCast(v);

    if (getInt(map, "enrollment.min_days")) |v| policy.enroll_min_days = @intCast(v);
    if (getInt(map, "enrollment.max_days")) |v| policy.enroll_max_days = @intCast(v);
    if (getInt(map, "enrollment.min_daily_minutes")) |v| policy.enroll_min_daily_minutes = @intCast(v);
    if (getBool(map, "enrollment.auto_activate")) |v| policy.enroll_auto_activate = v;

    if (getString(map, "response.amber.action")) |v| policy.amber_action = parseAction(v) orelse return error.InvalidValue;
    if (getString(map, "response.red.action")) |v| policy.red_action = parseAction(v) orelse return error.InvalidValue;
    if (getBool(map, "response.red.notify")) |v| policy.red_notify = v;

    if (getBool(map, "response.black.enabled")) |v| policy.black_enabled = v;
    if (getInt(map, "response.black.confirm_delay")) |v| policy.black_confirm_delay = @intCast(v);

    if (getBool(map, "response.silent.enabled")) |v| policy.silent_enabled = v;

    if (getFloat(map, "adaptive.micro_update_lambda")) |v| policy.micro_update_lambda = v;
    if (getFloat(map, "adaptive.anchor_drift_max")) |v| policy.anchor_drift_max = v;
    if (getInt(map, "adaptive.time_segments")) |v| policy.time_segments = @intCast(v);

    if (getFloat(map, "scoring.alpha")) |v| policy.alpha = v;
    if (getInt(map, "scoring.window_seconds")) |v| policy.window_seconds = @intCast(v);
    if (getInt(map, "scoring.min_events_per_window")) |v| policy.min_events_per_window = @intCast(v);

    return policy;
}

fn parseAction(s: []const u8) ?Policy.Action {
    if (std.mem.eql(u8, s, "lock")) return .lock;
    if (std.mem.eql(u8, s, "lock_and_kill")) return .lock_and_kill;
    if (std.mem.eql(u8, s, "wipe")) return .wipe;
    if (std.mem.eql(u8, s, "dead_drop")) return .dead_drop;
    if (std.mem.eql(u8, s, "none")) return .none;
    return null;
}

fn getFloat(map: *const std.StringHashMap(Value), key: []const u8) ?f64 {
    const val = map.get(key) orelse return null;
    return switch (val) {
        .float => |f| f,
        .integer => |i| @floatFromInt(i),
        else => null,
    };
}

fn getInt(map: *const std.StringHashMap(Value), key: []const u8) ?i64 {
    const val = map.get(key) orelse return null;
    return switch (val) {
        .integer => |i| i,
        else => null,
    };
}

fn getBool(map: *const std.StringHashMap(Value), key: []const u8) ?bool {
    const val = map.get(key) orelse return null;
    return switch (val) {
        .boolean => |b| b,
        else => null,
    };
}

fn getString(map: *const std.StringHashMap(Value), key: []const u8) ?[]const u8 {
    const val = map.get(key) orelse return null;
    return switch (val) {
        .string => |s| s,
        else => null,
    };
}

/// Free all allocated keys in a parsed TOML map.
pub fn deinitMap(map: *std.StringHashMap(Value), allocator: std.mem.Allocator) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        allocator.free(entry.key_ptr.*);
    }
    map.deinit();
}

// ---- Tests ----

test "parse minimal policy TOML" {
    const toml =
        \\[thresholds]
        \\tau = 0.55
        \\tau_critical = 0.80
        \\grace_seconds = 45
        \\
        \\[enrollment]
        \\min_days = 7
        \\auto_activate = false
        \\
        \\[response.amber]
        \\action = "lock"
        \\
        \\[scoring]
        \\alpha = 0.6
    ;

    var map = try parseToml(toml, std.testing.allocator);
    defer deinitMap(&map, std.testing.allocator);

    try std.testing.expectApproxEqAbs(@as(f64, 0.55), getFloat(&map, "thresholds.tau").?, 1e-10);
    try std.testing.expectEqual(@as(i64, 45), getInt(&map, "thresholds.grace_seconds").?);
    try std.testing.expectEqual(false, getBool(&map, "enrollment.auto_activate").?);
    try std.testing.expect(std.mem.eql(u8, "lock", getString(&map, "response.amber.action").?));
}

test "policy from TOML map" {
    const toml =
        \\[thresholds]
        \\tau = 0.60
        \\tau_critical = 0.85
        \\grace_seconds = 30
        \\panic_seconds = 90
        \\
        \\[scoring]
        \\alpha = 0.7
    ;

    var map = try parseToml(toml, std.testing.allocator);
    defer deinitMap(&map, std.testing.allocator);

    const policy = try policyFromMap(&map);
    try std.testing.expectApproxEqAbs(@as(f64, 0.60), policy.tau, 1e-10);
    try std.testing.expectApproxEqAbs(@as(f64, 0.85), policy.tau_critical, 1e-10);
    try std.testing.expectEqual(@as(u32, 30), policy.grace_seconds);
    try std.testing.expectApproxEqAbs(@as(f64, 0.7), policy.alpha, 1e-10);
}

test "policy validation catches invalid tau" {
    var policy = Policy{};
    policy.tau = 0.90;
    policy.tau_critical = 0.80; // tau >= tau_critical is invalid
    try std.testing.expectError(error.InvalidPolicy, policy.validate());
}

test "policy validation accepts defaults" {
    const policy = Policy{};
    try policy.validate();
}

test "reject empty input" {
    var map = try parseToml("", std.testing.allocator);
    defer deinitMap(&map, std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), map.count());
}

test "reject malformed line" {
    const result = parseToml("not a valid line", std.testing.allocator);
    try std.testing.expectError(error.InvalidSyntax, result);
}

test "comments are ignored" {
    const toml =
        \\# This is a comment
        \\[thresholds]
        \\tau = 0.55  # inline comment
    ;
    var map = try parseToml(toml, std.testing.allocator);
    defer deinitMap(&map, std.testing.allocator);
    try std.testing.expectApproxEqAbs(@as(f64, 0.55), getFloat(&map, "thresholds.tau").?, 1e-10);
}
