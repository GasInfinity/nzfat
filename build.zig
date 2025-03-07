const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const nzfat = b.addModule("nzfat", .{
        .root_source_file = b.path("src/nzfat.zig"),
        .target = target,
        .optimize = optimize,
    });

    // This is a simple test app to open images
    const exe = b.addExecutable(.{
        .name = "nzfat",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.root_module.addImport("nzfat", nzfat);
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const nzfat_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/nzfat.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_nzfat_unit_tests = b.addRunArtifact(nzfat_unit_tests);

    const exe_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_nzfat_unit_tests.step);
    test_step.dependOn(&run_exe_unit_tests.step);
}
