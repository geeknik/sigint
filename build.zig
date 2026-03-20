const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // -- Compile-time options --
    const wipe_support = b.option(bool, "wipe_support", "Include BLACK response wipe code (default: false)") orelse false;
    const max_window_ms = b.option(u32, "max_window_ms", "Maximum scoring window in milliseconds (default: 30000)") orelse 30000;
    const min_events = b.option(u32, "min_events", "Minimum events per scoring window (default: 40)") orelse 40;
    const feature_dim = b.option(u32, "feature_dim", "Feature vector dimension (default: 30)") orelse 30;

    // Build options module shared by all binaries
    const options = b.addOptions();
    options.addOption(bool, "wipe_support", wipe_support);
    options.addOption(u32, "max_window_ms", max_window_ms);
    options.addOption(u32, "min_events", min_events);
    options.addOption(u32, "feature_dim", feature_dim);

    // -- Shared common module --
    const common_mod = b.addModule("sigint_common", .{
        .root_source_file = b.path("src/common/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    common_mod.addOptions("build_options", options);

    // -- Binary definitions --
    const binary_configs = [_]struct { name: []const u8, source: []const u8 }{
        .{ .name = "sigint-collector", .source = "src/collector/main.zig" },
        .{ .name = "sigint-analyzer", .source = "src/analyzer/main.zig" },
        .{ .name = "sigint-enforcer", .source = "src/enforcer/main.zig" },
        .{ .name = "sigint-ctl", .source = "src/ctl/main.zig" },
    };

    for (binary_configs) |cfg| {
        const exe_mod = b.createModule(.{
            .root_source_file = b.path(cfg.source),
            .target = target,
            .optimize = optimize,
        });
        exe_mod.addImport("sigint_common", common_mod);

        const exe = b.addExecutable(.{
            .name = cfg.name,
            .root_module = exe_mod,
        });
        b.installArtifact(exe);
    }

    // -- Tests --
    const test_step = b.step("test", "Run all unit tests");

    // Test the common module
    const common_test_mod = b.createModule(.{
        .root_source_file = b.path("src/common/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    common_test_mod.addOptions("build_options", options);
    const common_tests = b.addTest(.{
        .root_module = common_test_mod,
    });
    const run_common_tests = b.addRunArtifact(common_tests);
    test_step.dependOn(&run_common_tests.step);

    // Integration tests in tests/ directory
    const integration_test_files = [_][]const u8{
        "tests/test_scoring.zig",
    };

    for (integration_test_files) |test_file| {
        if (std.fs.cwd().access(test_file, .{})) {
            const t_mod = b.createModule(.{
                .root_source_file = b.path(test_file),
                .target = target,
                .optimize = optimize,
            });
            t_mod.addImport("sigint_common", common_mod);
            const t = b.addTest(.{ .root_module = t_mod });
            const run_t = b.addRunArtifact(t);
            test_step.dependOn(&run_t.step);
        } else |_| {}
    }
}
