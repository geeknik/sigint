// Time-of-day segmentation for adaptive baseline modeling.
//
// SIGINT builds separate sub-profiles for four time segments,
// accounting for natural variation in typing patterns across the day
// (morning alertness vs. evening fatigue, etc.).

/// Time-of-day segment for adaptive profiling.
pub const Segment = enum(u2) {
    /// 00:00 — 05:59
    night = 0,
    /// 06:00 — 11:59
    morning = 1,
    /// 12:00 — 17:59
    afternoon = 2,
    /// 18:00 — 23:59
    evening = 3,
};

/// Determine the time segment for a given hour (0-23).
pub fn segment(hour: u5) Segment {
    return if (hour < 6)
        .night
    else if (hour < 12)
        .morning
    else if (hour < 18)
        .afternoon
    else
        .evening;
}

/// Get the current time segment from the system clock.
pub fn currentSegment() Segment {
    const epoch = @import("std").time.timestamp();
    // Extract hour from Unix timestamp (UTC). For local time, the caller
    // should apply a timezone offset before calling segment().
    const seconds_in_day = @mod(epoch, 86400);
    const hour: u5 = @intCast(@divTrunc(seconds_in_day, 3600));
    return segment(hour);
}

test "segment boundaries" {
    const testing = @import("std").testing;
    try testing.expectEqual(Segment.night, segment(0));
    try testing.expectEqual(Segment.night, segment(5));
    try testing.expectEqual(Segment.morning, segment(6));
    try testing.expectEqual(Segment.morning, segment(11));
    try testing.expectEqual(Segment.afternoon, segment(12));
    try testing.expectEqual(Segment.afternoon, segment(17));
    try testing.expectEqual(Segment.evening, segment(18));
    try testing.expectEqual(Segment.evening, segment(23));
}
