// Scoring engine for keystroke biometric verification.
//
// Combines two sub-models:
// 1. Mahalanobis distance against the enrolled feature profile (global rhythm)
// 2. Per-digraph Z-score ensemble (catches adversaries who match global cadence
//    but fail on specific key-pair timing)
//
// Both sub-scores are normalized to [0, 1] and combined with configurable weight.

const std = @import("std");
const math = std.math;
const linalg = @import("math_linalg.zig");
const features_mod = @import("features.zig");
const options = @import("build_options");

pub const N: usize = options.feature_dim;

/// Per-digraph univariate statistics from enrollment.
pub const DigraphStat = struct {
    mean: f64 = 0,
    stddev: f64 = 0,
    count: u32 = 0,
};

/// Model for a single time-of-day segment.
pub const SegmentModel = struct {
    mu: [N]f64 = [_]f64{0} ** N,
    cholesky_L: [N][N]f64 = [_][N]f64{[_]f64{0} ** N} ** N,
    sample_count: u32 = 0,

    /// Per-digraph univariate stats for Z-score ensemble.
    digraph_stats: [features_mod.num_digraph_features]DigraphStat =
        [_]DigraphStat{.{}} ** features_mod.num_digraph_features,

    /// Build the Cholesky factor from a covariance matrix.
    pub fn setCovariance(self: *SegmentModel, sigma: *const [N][N]f64) !void {
        try linalg.choleskyDecompose(sigma, &self.cholesky_L);
    }
};

/// Score a feature vector against a segment model using Mahalanobis distance.
/// Returns a normalized score in [0, 1] where 0 = perfect match, 1 = total stranger.
pub fn scoreMahalanobis(fv: *const features_mod.FeatureVector, model: *const SegmentModel) f64 {
    if (model.sample_count == 0) return 0;

    const d_sq = linalg.mahalanobisDistanceSq(&fv.values, &model.mu, &model.cholesky_L);

    // Normalize via chi-squared CDF: P(chi2(N) <= d^2)
    // This gives the probability that a sample from the enrolled distribution
    // would have a distance <= d. High values mean "this is very unlikely to
    // be the enrolled user."
    return linalg.chi2Cdf(d_sq, @intCast(N));
}

/// Score using per-digraph Z-score ensemble.
/// For each tracked digraph with sufficient data, compute |z| = |x - mean| / stddev.
/// Returns the median |z| across all observed digraphs.
/// Returns 0 if no digraph data is available.
pub fn scoreDigraphEnsemble(fv: *const features_mod.FeatureVector, model: *const SegmentModel) f64 {
    var z_scores: [features_mod.num_digraph_features]f64 = undefined;
    var z_count: usize = 0;

    for (0..features_mod.num_digraph_features) |i| {
        const stat = model.digraph_stats[i];
        const count = fv.digraph_counts[i];

        // Need both enrollment data and current window data
        if (stat.count < 5 or count == 0 or stat.stddev <= 0) continue;

        const z = @abs(fv.values[i] - stat.mean) / stat.stddev;
        z_scores[z_count] = z;
        z_count += 1;
    }

    if (z_count == 0) return 0;

    // Sort and take median
    std.mem.sort(f64, z_scores[0..z_count], {}, std.sort.asc(f64));
    const median_z = z_scores[z_count / 2];

    // Normalize: Z-score of 0 → score 0, Z-score of 3+ → score ~1
    // Use the standard normal CDF: P(|Z| <= z) = 2*Phi(z) - 1
    // We want P(|Z| > z) = 2*(1 - Phi(z)) as our anomaly score
    return 2.0 * (1.0 - normalCdfApprox(median_z));
}

/// Combined score from both sub-models.
/// alpha: weight for Mahalanobis (default 0.6 per DESIGN.md).
pub fn scoreCombined(mahal_score: f64, digraph_score: f64, alpha: f64) f64 {
    return alpha * mahal_score + (1.0 - alpha) * digraph_score;
}

/// Normal CDF approximation for scoring normalization.
fn normalCdfApprox(x: f64) f64 {
    if (x < -8.0) return 0.0;
    if (x > 8.0) return 1.0;

    const a1: f64 = 0.254829592;
    const a2: f64 = -0.284496736;
    const a3: f64 = 1.421413741;
    const a4: f64 = -1.453152027;
    const a5: f64 = 1.061405429;
    const p: f64 = 0.3275911;

    const sign: f64 = if (x < 0) -1.0 else 1.0;
    const abs_x = @abs(x);
    const t = 1.0 / (1.0 + p * abs_x);
    const y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * @exp(-abs_x * abs_x / 2.0);

    return 0.5 * (1.0 + sign * y);
}

// ---- Tests ----

test "Mahalanobis score zero for enrolled user mean" {
    var model = SegmentModel{};
    model.sample_count = 100;
    // Identity covariance
    for (0..N) |i| {
        model.cholesky_L[i][i] = 1.0;
        model.mu[i] = 5.0;
    }

    var fv = features_mod.FeatureVector{};
    for (0..N) |i| {
        fv.values[i] = 5.0; // matches mean exactly
    }

    const score = scoreMahalanobis(&fv, &model);
    // Score should be very low (near 0) for exact match
    try std.testing.expect(score < 0.01);
}

test "Mahalanobis score high for outlier" {
    var model = SegmentModel{};
    model.sample_count = 100;
    for (0..N) |i| {
        model.cholesky_L[i][i] = 1.0;
        model.mu[i] = 0.0;
    }

    var fv = features_mod.FeatureVector{};
    for (0..N) |i| {
        fv.values[i] = 10.0; // far from mean
    }

    const score = scoreMahalanobis(&fv, &model);
    // Score should be high (near 1) for outlier
    try std.testing.expect(score > 0.99);
}

test "digraph ensemble score zero when no data" {
    const model = SegmentModel{};
    const fv = features_mod.FeatureVector{};
    const score = scoreDigraphEnsemble(&fv, &model);
    try std.testing.expectApproxEqAbs(@as(f64, 0.0), score, 1e-10);
}

test "combined score respects alpha weight" {
    const combined = scoreCombined(1.0, 0.0, 0.6);
    try std.testing.expectApproxEqAbs(@as(f64, 0.6), combined, 1e-10);

    const combined2 = scoreCombined(0.0, 1.0, 0.6);
    try std.testing.expectApproxEqAbs(@as(f64, 0.4), combined2, 1e-10);
}

test "combined score with equal weight" {
    const combined = scoreCombined(0.5, 0.5, 0.5);
    try std.testing.expectApproxEqAbs(@as(f64, 0.5), combined, 1e-10);
}
