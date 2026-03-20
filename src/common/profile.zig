// Profile data structure and binary serialization.
//
// A Profile contains the enrolled user's biometric model: mean vectors,
// Cholesky factors, per-digraph statistics, and metadata. Profiles are
// serialized to a fixed-layout binary format and encrypted at rest using
// AES-256-GCM via crypto_util.

const std = @import("std");
const options = @import("build_options");
const scoring = @import("scoring.zig");
const features_mod = @import("features.zig");
const linalg = @import("math_linalg.zig");

pub const N: usize = options.feature_dim;
pub const num_segments: usize = 4;
pub const num_digraphs: usize = features_mod.num_digraph_features;

/// Current profile format version.
pub const format_version: u32 = 1;

/// Magic bytes for profile file identification.
pub const profile_magic = [4]u8{ 'S', 'P', 'R', 'F' };

/// Complete biometric profile for a user.
pub const Profile = struct {
    version: u32 = format_version,
    uid: u32 = 0,
    enrollment_start: i64 = 0,
    enrollment_end: i64 = 0,

    /// Live models (updated via micro-updates during verification).
    segments: [num_segments]scoring.SegmentModel = [_]scoring.SegmentModel{.{}} ** num_segments,

    /// Frozen anchor models from enrollment completion — never micro-updated.
    anchor_segments: [num_segments]scoring.SegmentModel = [_]scoring.SegmentModel{.{}} ** num_segments,

    /// Enrollment quality metadata.
    total_events: u64 = 0,
    digraph_coverage: f64 = 0,
    quality_score: f64 = 0,

    /// Serialize the profile header (metadata) to a byte buffer.
    /// The full profile is large (multiple segment models with NxN matrices),
    /// so we serialize it in parts.
    pub fn headerSize() usize {
        return 4 + // magic
            4 + // version
            4 + // uid
            8 + // enrollment_start
            8 + // enrollment_end
            8 + // total_events
            8 + // digraph_coverage
            8; // quality_score
    }

    /// Size of a single SegmentModel in serialized form.
    pub fn segmentModelSize() usize {
        return N * 8 + // mu: [N]f64
            N * N * 8 + // cholesky_L: [N][N]f64
            4 + // sample_count: u32
            num_digraphs * (8 + 8 + 4); // digraph_stats: [num_digraphs]DigraphStat (mean f64 + stddev f64 + count u32)
    }

    /// Total serialized size.
    pub fn totalSize() usize {
        return headerSize() + 2 * num_segments * segmentModelSize();
    }

    /// Serialize the entire profile to a byte buffer.
    pub fn serialize(self: *const Profile, out: []u8) error{BufferTooSmall}!usize {
        const total = totalSize();
        if (out.len < total) return error.BufferTooSmall;

        var pos: usize = 0;

        // Header
        @memcpy(out[pos..][0..4], &profile_magic);
        pos += 4;
        std.mem.writeInt(u32, out[pos..][0..4], self.version, .little);
        pos += 4;
        std.mem.writeInt(u32, out[pos..][0..4], self.uid, .little);
        pos += 4;
        std.mem.writeInt(i64, out[pos..][0..8], self.enrollment_start, .little);
        pos += 8;
        std.mem.writeInt(i64, out[pos..][0..8], self.enrollment_end, .little);
        pos += 8;
        std.mem.writeInt(u64, out[pos..][0..8], self.total_events, .little);
        pos += 8;
        writeF64(out[pos..][0..8], self.digraph_coverage);
        pos += 8;
        writeF64(out[pos..][0..8], self.quality_score);
        pos += 8;

        // Live segments
        for (0..num_segments) |s| {
            pos = serializeSegmentModel(&self.segments[s], out, pos);
        }

        // Anchor segments
        for (0..num_segments) |s| {
            pos = serializeSegmentModel(&self.anchor_segments[s], out, pos);
        }

        return pos;
    }

    /// Deserialize a profile from a byte buffer.
    pub fn deserialize(buf: []const u8) error{ BufferTooSmall, InvalidMagic, UnsupportedVersion }!Profile {
        const total = totalSize();
        if (buf.len < total) return error.BufferTooSmall;

        var pos: usize = 0;

        // Verify magic
        if (!std.mem.eql(u8, buf[0..4], &profile_magic)) return error.InvalidMagic;
        pos += 4;

        var profile = Profile{};

        profile.version = std.mem.readInt(u32, buf[pos..][0..4], .little);
        pos += 4;
        if (profile.version != format_version) return error.UnsupportedVersion;

        profile.uid = std.mem.readInt(u32, buf[pos..][0..4], .little);
        pos += 4;
        profile.enrollment_start = std.mem.readInt(i64, buf[pos..][0..8], .little);
        pos += 8;
        profile.enrollment_end = std.mem.readInt(i64, buf[pos..][0..8], .little);
        pos += 8;
        profile.total_events = std.mem.readInt(u64, buf[pos..][0..8], .little);
        pos += 8;
        profile.digraph_coverage = readF64(buf[pos..][0..8]);
        pos += 8;
        profile.quality_score = readF64(buf[pos..][0..8]);
        pos += 8;

        // Live segments
        for (0..num_segments) |s| {
            pos = deserializeSegmentModel(&profile.segments[s], buf, pos);
        }

        // Anchor segments
        for (0..num_segments) |s| {
            pos = deserializeSegmentModel(&profile.anchor_segments[s], buf, pos);
        }

        return profile;
    }
};

fn serializeSegmentModel(model: *const scoring.SegmentModel, out: []u8, start_pos: usize) usize {
    var pos = start_pos;

    // mu
    for (0..N) |i| {
        writeF64(out[pos..][0..8], model.mu[i]);
        pos += 8;
    }

    // cholesky_L
    for (0..N) |i| {
        for (0..N) |j| {
            writeF64(out[pos..][0..8], model.cholesky_L[i][j]);
            pos += 8;
        }
    }

    // sample_count
    std.mem.writeInt(u32, out[pos..][0..4], model.sample_count, .little);
    pos += 4;

    // digraph_stats
    for (0..num_digraphs) |i| {
        writeF64(out[pos..][0..8], model.digraph_stats[i].mean);
        pos += 8;
        writeF64(out[pos..][0..8], model.digraph_stats[i].stddev);
        pos += 8;
        std.mem.writeInt(u32, out[pos..][0..4], model.digraph_stats[i].count, .little);
        pos += 4;
    }

    return pos;
}

fn deserializeSegmentModel(model: *scoring.SegmentModel, buf: []const u8, start_pos: usize) usize {
    var pos = start_pos;

    for (0..N) |i| {
        model.mu[i] = readF64(buf[pos..][0..8]);
        pos += 8;
    }

    for (0..N) |i| {
        for (0..N) |j| {
            model.cholesky_L[i][j] = readF64(buf[pos..][0..8]);
            pos += 8;
        }
    }

    model.sample_count = std.mem.readInt(u32, buf[pos..][0..4], .little);
    pos += 4;

    for (0..num_digraphs) |i| {
        model.digraph_stats[i].mean = readF64(buf[pos..][0..8]);
        pos += 8;
        model.digraph_stats[i].stddev = readF64(buf[pos..][0..8]);
        pos += 8;
        model.digraph_stats[i].count = std.mem.readInt(u32, buf[pos..][0..4], .little);
        pos += 4;
    }

    return pos;
}

fn writeF64(buf: *[8]u8, val: f64) void {
    buf.* = @bitCast(val);
}

fn readF64(buf: *const [8]u8) f64 {
    return @bitCast(buf.*);
}

// ---- Tests ----

test "profile round-trip serialization" {
    var profile = Profile{};
    profile.uid = 1000;
    profile.enrollment_start = 1711929600;
    profile.enrollment_end = 1712534400;
    profile.total_events = 150000;
    profile.digraph_coverage = 0.92;
    profile.quality_score = 0.88;

    // Set some segment model data
    profile.segments[0].mu[0] = 85_000_000; // 85ms mean dwell
    profile.segments[0].sample_count = 5000;
    profile.segments[0].cholesky_L[0][0] = 1.5;
    profile.segments[0].digraph_stats[0] = .{
        .mean = 120_000_000,
        .stddev = 15_000_000,
        .count = 500,
    };

    // Copy to anchor
    profile.anchor_segments[0] = profile.segments[0];

    const size = Profile.totalSize();
    const buf = try std.testing.allocator.alloc(u8, size);
    defer std.testing.allocator.free(buf);

    const written = try profile.serialize(buf);
    try std.testing.expectEqual(size, written);

    const restored = try Profile.deserialize(buf);
    try std.testing.expectEqual(@as(u32, 1000), restored.uid);
    try std.testing.expectEqual(@as(i64, 1711929600), restored.enrollment_start);
    try std.testing.expectEqual(@as(u64, 150000), restored.total_events);
    try std.testing.expectApproxEqAbs(@as(f64, 0.92), restored.digraph_coverage, 1e-10);
    try std.testing.expectApproxEqAbs(@as(f64, 85_000_000), restored.segments[0].mu[0], 1e-6);
    try std.testing.expectEqual(@as(u32, 5000), restored.segments[0].sample_count);
    try std.testing.expectApproxEqAbs(@as(f64, 1.5), restored.segments[0].cholesky_L[0][0], 1e-10);
    try std.testing.expectApproxEqAbs(@as(f64, 120_000_000), restored.segments[0].digraph_stats[0].mean, 1e-6);
    try std.testing.expectEqual(@as(u32, 500), restored.segments[0].digraph_stats[0].count);
}

test "profile rejects invalid magic" {
    const size = Profile.totalSize();
    const buf = try std.testing.allocator.alloc(u8, size);
    defer std.testing.allocator.free(buf);
    @memset(buf, 0);
    buf[0] = 'X'; // wrong magic
    const result = Profile.deserialize(buf);
    try std.testing.expectError(error.InvalidMagic, result);
}

test "profile rejects too-small buffer" {
    const buf = [_]u8{0} ** 10;
    const result = Profile.deserialize(&buf);
    try std.testing.expectError(error.BufferTooSmall, result);
}

test "profile size is deterministic" {
    // With N=30 and 20 digraphs:
    // header = 52
    // segment = 30*8 + 30*30*8 + 4 + 20*(8+8+4) = 240 + 7200 + 4 + 400 = 7844
    // total = 52 + 2*4*7844 = 52 + 62752 = 62804
    const expected_segment = N * 8 + N * N * 8 + 4 + num_digraphs * 20;
    try std.testing.expectEqual(Profile.segmentModelSize(), expected_segment);
    try std.testing.expectEqual(Profile.totalSize(), Profile.headerSize() + 2 * num_segments * expected_segment);
}
