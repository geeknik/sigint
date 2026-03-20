// Linear algebra primitives for keystroke biometric scoring.
//
// Implements Welford's online mean/covariance accumulator, Cholesky
// decomposition with Tikhonov regularization, Mahalanobis distance via
// forward/back substitution (never explicitly inverts), and chi-squared
// CDF for score normalization.
//
// All operations work on comptime-sized f64 arrays. For N=30 (default),
// a covariance matrix is 30*30*8 = 7,200 bytes — fits comfortably on stack.

const std = @import("std");
const math = std.math;
const options = @import("build_options");

pub const N: usize = options.feature_dim;

/// Online mean and covariance accumulator using Welford's algorithm.
/// Numerically stable for large sample counts.
pub const WelfordState = struct {
    count: u64 = 0,
    mean: [N]f64 = [_]f64{0} ** N,
    // M2[i][j] accumulates the sum of (x_i - mean_i)(x_j - mean_j)
    m2: [N][N]f64 = [_][N]f64{[_]f64{0} ** N} ** N,

    /// Add a new sample to the running statistics.
    pub fn update(self: *WelfordState, sample: *const [N]f64) void {
        self.count += 1;
        const n: f64 = @floatFromInt(self.count);

        var delta: [N]f64 = undefined;
        for (0..N) |i| {
            delta[i] = sample[i] - self.mean[i];
        }

        for (0..N) |i| {
            self.mean[i] += delta[i] / n;
        }

        // After updating mean, compute delta2 = sample - new_mean
        var delta2: [N]f64 = undefined;
        for (0..N) |i| {
            delta2[i] = sample[i] - self.mean[i];
        }
        for (0..N) |i| {
            for (0..N) |j| {
                self.m2[i][j] += delta[i] * delta2[j];
            }
        }
    }

    /// Finalize: extract the sample covariance matrix (N-1 denominator).
    /// Applies Tikhonov regularization (adds epsilon to diagonal).
    pub fn finalize(self: *const WelfordState, mu: *[N]f64, sigma: *[N][N]f64) void {
        const regularization_epsilon: f64 = 1e-6;

        @memcpy(mu, &self.mean);

        if (self.count < 2) {
            // Not enough data — return identity-like matrix
            for (0..N) |i| {
                for (0..N) |j| {
                    sigma[i][j] = if (i == j) regularization_epsilon else 0;
                }
            }
            return;
        }

        const n_minus_1: f64 = @floatFromInt(self.count - 1);
        for (0..N) |i| {
            for (0..N) |j| {
                sigma[i][j] = self.m2[i][j] / n_minus_1;
            }
            sigma[i][i] += regularization_epsilon;
        }
    }
};

/// Cholesky decomposition: compute lower-triangular L such that sigma = L * L^T.
/// Input must be symmetric positive-definite (guaranteed by Welford + regularization).
/// Returns error if matrix is not positive-definite.
pub fn choleskyDecompose(sigma: *const [N][N]f64, L: *[N][N]f64) error{NotPositiveDefinite}!void {
    for (0..N) |i| {
        for (0..N) |j| {
            L[i][j] = 0;
        }
    }

    for (0..N) |j| {
        var sum: f64 = 0;
        for (0..j) |k| {
            sum += L[j][k] * L[j][k];
        }
        const diag = sigma[j][j] - sum;
        if (diag <= 0) return error.NotPositiveDefinite;
        L[j][j] = @sqrt(diag);

        for (j + 1..N) |i| {
            var s: f64 = 0;
            for (0..j) |k| {
                s += L[i][k] * L[j][k];
            }
            L[i][j] = (sigma[i][j] - s) / L[j][j];
        }
    }
}

/// Solve L * x = b via forward substitution where L is lower-triangular.
pub fn forwardSubstitute(L: *const [N][N]f64, b: *const [N]f64, x: *[N]f64) void {
    for (0..N) |i| {
        var sum: f64 = 0;
        for (0..i) |j| {
            sum += L[i][j] * x[j];
        }
        x[i] = (b[i] - sum) / L[i][i];
    }
}

/// Compute Mahalanobis distance using the Cholesky factor.
/// d = ||L^{-1} * (x - mu)||_2
pub fn mahalanobisDistance(x: *const [N]f64, mu: *const [N]f64, L: *const [N][N]f64) f64 {
    var diff: [N]f64 = undefined;
    for (0..N) |i| {
        diff[i] = x[i] - mu[i];
    }

    var y: [N]f64 = undefined;
    forwardSubstitute(L, &diff, &y);

    var sum_sq: f64 = 0;
    for (0..N) |i| {
        sum_sq += y[i] * y[i];
    }

    return @sqrt(sum_sq);
}

/// Squared Mahalanobis distance (avoids the sqrt for CDF computation).
pub fn mahalanobisDistanceSq(x: *const [N]f64, mu: *const [N]f64, L: *const [N][N]f64) f64 {
    var diff: [N]f64 = undefined;
    for (0..N) |i| {
        diff[i] = x[i] - mu[i];
    }

    var y: [N]f64 = undefined;
    forwardSubstitute(L, &diff, &y);

    var sum_sq: f64 = 0;
    for (0..N) |i| {
        sum_sq += y[i] * y[i];
    }

    return sum_sq;
}

/// Standard normal CDF approximation (Abramowitz and Stegun).
/// Accuracy: max error < 1.5e-7.
fn normalCdf(x: f64) f64 {
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

/// Chi-squared CDF approximation via Wilson-Hilferty transformation.
/// P(X <= x) where X ~ chi2(k).
/// The squared Mahalanobis distance follows chi2(N) under the enrolled distribution.
pub fn chi2Cdf(x: f64, k: u32) f64 {
    if (x <= 0) return 0.0;
    if (k == 0) return 1.0;

    const kf: f64 = @floatFromInt(k);
    const ratio = x / kf;

    // Wilson-Hilferty: cube-root transformation to approximate normality
    const cbrt_ratio = math.cbrt(ratio);
    const correction = 1.0 - 2.0 / (9.0 * kf);
    const scale = @sqrt(2.0 / (9.0 * kf));

    if (scale == 0) return if (x >= kf) 1.0 else 0.0;

    const z = (cbrt_ratio - correction) / scale;
    return normalCdf(z);
}

/// Exponential moving average update for a vector.
/// new_value = (1 - lambda) * current + lambda * sample
pub fn emaUpdate(current: *[N]f64, sample: *const [N]f64, lambda: f64) void {
    const one_minus_lambda = 1.0 - lambda;
    for (0..N) |i| {
        current[i] = one_minus_lambda * current[i] + lambda * sample[i];
    }
}

/// Euclidean distance between two vectors (for anchor drift check).
pub fn euclideanDistance(a: *const [N]f64, b: *const [N]f64) f64 {
    var sum_sq: f64 = 0;
    for (0..N) |i| {
        const d = a[i] - b[i];
        sum_sq += d * d;
    }
    return @sqrt(sum_sq);
}

// ---- Tests ----

test "Welford mean computation" {
    var state = WelfordState{};

    // Simple test with known mean
    var s1: [N]f64 = [_]f64{0} ** N;
    var s2: [N]f64 = [_]f64{0} ** N;
    s1[0] = 10;
    s2[0] = 20;
    s1[1] = 100;
    s2[1] = 200;

    state.update(&s1);
    state.update(&s2);

    var mu: [N]f64 = undefined;
    var sigma: [N][N]f64 = undefined;
    state.finalize(&mu, &sigma);

    try std.testing.expectApproxEqAbs(@as(f64, 15.0), mu[0], 1e-10);
    try std.testing.expectApproxEqAbs(@as(f64, 150.0), mu[1], 1e-10);
}

test "Welford covariance computation" {
    var state = WelfordState{};

    // 4 samples: perfectly correlated x0 and x1
    const samples = [_][2]f64{
        .{ 1, 2 },
        .{ 3, 6 },
        .{ 5, 10 },
        .{ 7, 14 },
    };

    for (samples) |s| {
        var vec: [N]f64 = [_]f64{0} ** N;
        vec[0] = s[0];
        vec[1] = s[1];
        state.update(&vec);
    }

    var mu: [N]f64 = undefined;
    var sigma: [N][N]f64 = undefined;
    state.finalize(&mu, &sigma);

    // Mean of {1,3,5,7} = 4, {2,6,10,14} = 8
    try std.testing.expectApproxEqAbs(@as(f64, 4.0), mu[0], 1e-10);
    try std.testing.expectApproxEqAbs(@as(f64, 8.0), mu[1], 1e-10);

    // Var of {1,3,5,7} = 20/3, Var of {2,6,10,14} = 80/3
    // Cov(x0,x1) = 40/3
    try std.testing.expectApproxEqAbs(@as(f64, 20.0 / 3.0), sigma[0][0], 1e-4);
    try std.testing.expectApproxEqAbs(@as(f64, 80.0 / 3.0), sigma[1][1], 1e-4);
    try std.testing.expectApproxEqAbs(@as(f64, 40.0 / 3.0), sigma[0][1], 1e-4);
}

test "Cholesky decomposition of identity" {
    var sigma: [N][N]f64 = [_][N]f64{[_]f64{0} ** N} ** N;
    for (0..N) |i| {
        sigma[i][i] = 1.0;
    }

    var L: [N][N]f64 = undefined;
    try choleskyDecompose(&sigma, &L);

    // Cholesky of identity is identity
    for (0..N) |i| {
        for (0..N) |j| {
            const expected: f64 = if (i == j) 1.0 else 0.0;
            try std.testing.expectApproxEqAbs(expected, L[i][j], 1e-10);
        }
    }
}

test "Cholesky decomposition of 2x2" {
    // sigma = [[4, 2], [2, 3]] → L = [[2, 0], [1, sqrt(2)]]
    var sigma: [N][N]f64 = [_][N]f64{[_]f64{0} ** N} ** N;
    for (0..N) |i| {
        sigma[i][i] = 1.0; // identity for unused dims
    }
    sigma[0][0] = 4;
    sigma[0][1] = 2;
    sigma[1][0] = 2;
    sigma[1][1] = 3;

    var L: [N][N]f64 = undefined;
    try choleskyDecompose(&sigma, &L);

    try std.testing.expectApproxEqAbs(@as(f64, 2.0), L[0][0], 1e-10);
    try std.testing.expectApproxEqAbs(@as(f64, 0.0), L[0][1], 1e-10);
    try std.testing.expectApproxEqAbs(@as(f64, 1.0), L[1][0], 1e-10);
    try std.testing.expectApproxEqAbs(@sqrt(@as(f64, 2.0)), L[1][1], 1e-10);
}

test "Mahalanobis distance zero for mean" {
    var sigma: [N][N]f64 = [_][N]f64{[_]f64{0} ** N} ** N;
    for (0..N) |i| {
        sigma[i][i] = 1.0;
    }
    var L: [N][N]f64 = undefined;
    try choleskyDecompose(&sigma, &L);

    var mu: [N]f64 = [_]f64{0} ** N;
    mu[0] = 5.0;

    const d = mahalanobisDistance(&mu, &mu, &L);
    try std.testing.expectApproxEqAbs(@as(f64, 0.0), d, 1e-10);
}

test "Mahalanobis distance equals Euclidean for identity covariance" {
    var sigma: [N][N]f64 = [_][N]f64{[_]f64{0} ** N} ** N;
    for (0..N) |i| {
        sigma[i][i] = 1.0;
    }
    var L: [N][N]f64 = undefined;
    try choleskyDecompose(&sigma, &L);

    var mu: [N]f64 = [_]f64{0} ** N;
    var x: [N]f64 = [_]f64{0} ** N;
    x[0] = 3.0;
    x[1] = 4.0;

    const d = mahalanobisDistance(&x, &mu, &L);
    // sqrt(9 + 16) = 5
    try std.testing.expectApproxEqAbs(@as(f64, 5.0), d, 1e-10);
}

test "chi2 CDF basic properties" {
    // CDF(0) = 0
    try std.testing.expectApproxEqAbs(@as(f64, 0.0), chi2Cdf(0, 1), 1e-3);
    // CDF(very large) ≈ 1
    try std.testing.expect(chi2Cdf(1000, 10) > 0.99);
    // CDF at median of chi2(1) ≈ 0.5 at x ≈ 0.455
    const mid = chi2Cdf(0.455, 1);
    try std.testing.expect(mid > 0.4 and mid < 0.6);
}

test "EMA update" {
    var current: [N]f64 = [_]f64{10} ** N;
    var sample: [N]f64 = [_]f64{20} ** N;

    emaUpdate(&current, &sample, 0.1);

    // Expected: 0.9 * 10 + 0.1 * 20 = 11
    for (0..N) |i| {
        try std.testing.expectApproxEqAbs(@as(f64, 11.0), current[i], 1e-10);
    }
}

test "Euclidean distance" {
    var a: [N]f64 = [_]f64{0} ** N;
    var b: [N]f64 = [_]f64{0} ** N;
    a[0] = 3;
    b[1] = 4;

    try std.testing.expectApproxEqAbs(@as(f64, 5.0), euclideanDistance(&a, &b), 1e-10);
}
