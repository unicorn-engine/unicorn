//! License: GNU GENERAL PUBLIC LICENSE Version 2

const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    if (comptime !checkVersion())
        @compileError("Please! Update zig toolchain to >= v0.11!");
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    // flag: -DSamples=True/False
    const samples = b.option(bool, "Samples", "Build all Samples [default: true]") orelse true;

    // Build Samples

    if (samples) {
        // Zig
        buildExe(b, .{
            .target = target,
            .optimize = optimize,
            .filetype = .zig,
            .filepath = "bindings/zig/sample/sample_riscv_zig.zig",
        });

        // C
        buildExe(b, .{
            .target = target,
            .optimize = optimize,
            .filetype = .c,
            .filepath = "samples/sample_arm.c",
        });
        buildExe(b, .{
            .target = target,
            .optimize = optimize,
            .filetype = .c,
            .filepath = "samples/sample_arm64.c",
        });
        buildExe(b, .{
            .target = target,
            .optimize = optimize,
            .filetype = .c,
            .filepath = "samples/sample_ctl.c",
        });
        buildExe(b, .{
            .target = target,
            .optimize = optimize,
            .filetype = .c,
            .filepath = "samples/sample_batch_reg.c",
        });
        buildExe(b, .{
            .target = target,
            .optimize = optimize,
            .filetype = .c,
            .filepath = "samples/sample_m68k.c",
        });
        buildExe(b, .{
            .target = target,
            .optimize = optimize,
            .filetype = .c,
            .filepath = "samples/sample_riscv.c",
        });
        buildExe(b, .{
            .target = target,
            .optimize = optimize,
            .filetype = .c,
            .filepath = "samples/sample_sparc.c",
        });
        buildExe(b, .{
            .target = target,
            .optimize = optimize,
            .filetype = .c,
            .filepath = "samples/sample_s390x.c",
        });
        buildExe(b, .{
            .target = target,
            .optimize = optimize,
            .filetype = .c,
            .filepath = "samples/shellcode.c",
        });
        buildExe(b, .{
            .target = target,
            .optimize = optimize,
            .filetype = .c,
            .filepath = "samples/sample_tricore.c",
        });
        buildExe(b, .{
            .target = target,
            .optimize = optimize,
            .filetype = .c,
            .filepath = "samples/sample_x86.c",
        });
        buildExe(b, .{
            .target = target,
            .optimize = optimize,
            .filetype = .c,
            .filepath = "samples/sample_x86_32_gdt_and_seg_regs.c",
        });
    }

    // CMake Build
    const cmake = cmakeBuild(b);
    const cmake_step = b.step("cmake", "Run cmake build");
    cmake_step.dependOn(&cmake.step);
}

fn buildExe(b: *std.Build, info: BuildInfo) void {
    const execonfig: std.Build.ExecutableOptions = switch (info.filetype) {
        .c, .cpp => .{
            .name = info.filename(),
            .target = info.target,
            .optimize = info.optimize,
        },
        else => .{
            .name = info.filename(),
            .target = info.target,
            .optimize = info.optimize,
            .root_source_file = .{
                .path = info.filepath,
            },
        },
    };
    const unicornBuild = b.addExecutable(execonfig);

    if (info.filetype != .zig)
        unicornBuild.addCSourceFile(.{
            .file = .{ .path = info.filepath },
            .flags = &.{
                "-Wall",
                "-Werror",
                "-fno-sanitize=all",
                "-Wshadow",
            },
        })
    else
        unicornBuild.addAnonymousModule("unicorn", .{
            .source_file = .{
                .path = "bindings/zig/unicorn/unicorn.zig",
            },
        });
    unicornBuild.addIncludePath(.{ .path = "include" });
    // need run cmake before
    unicornBuild.addLibraryPath(.{ .path = "build" });
    if (info.target.isWindows()) {
        unicornBuild.want_lto = false;
        unicornBuild.linkSystemLibraryName("unicorn.dll");
    } else unicornBuild.linkSystemLibrary("unicorn");

    // linking to OS-LibC or static-linking for:
    // Musl(Linux) [e.g: -Dtarget=native-linux-musl]
    // MinGW(Windows) [e.g: -Dtarget=native-windows-gnu (default)]
    if (info.filetype == .cpp and info.target.getAbi() != .msvc)
        unicornBuild.linkLibCpp() // static-linking LLVM-libcxx (all targets) + libC
    else
        unicornBuild.linkLibC();

    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
    b.installArtifact(unicornBuild);

    // This *creates* a RunStep in the build graph, to be executed when another
    // step is evaluated that depends on it. The next line below will establish
    // such a dependency.
    const run_cmd = b.addRunArtifact(unicornBuild);

    // By making the run step depend on the install step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    // This is not necessary, however, if the application depends on other installed
    // files, this ensures they will be present and in the expected location.
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build run`
    // This will evaluate the `run` step rather than the default, which is "install".
    const run_step = b.step(info.filename(), b.fmt("Run the {s}.", .{info.filename()}));
    run_step.dependOn(&run_cmd.step);
}

fn cmakeBuild(b: *std.Build) *std.Build.Step.Run {
    const preconf = b.addSystemCommand(&.{
        "cmake",
        "-B",
        "build",
        "-DZIG_BUILD=ON",
        "-DUNICORN_BUILD_TESTS=OFF",
        "-DUNICORN_INSTALL=OFF",
        "-DCMAKE_BUILD_TYPE=Release",
    });
    const cmakebuild = b.addSystemCommand(&.{
        "cmake",
        "--build",
        "build",
        "--config",
        "release",
        "--parallel",
    });
    cmakebuild.step.dependOn(&preconf.step);
    return cmakebuild;
}

fn checkVersion() bool {
    const builtin = @import("builtin");
    if (!@hasDecl(builtin, "zig_version")) {
        return false;
    }

    const needed_version = std.SemanticVersion.parse("0.11.0") catch unreachable;
    const version = builtin.zig_version;
    const order = version.order(needed_version);
    return order != .lt;
}

const BuildInfo = struct {
    filepath: []const u8,
    filetype: enum {
        c,
        cpp,
        zig,
    },
    target: std.zig.CrossTarget,
    optimize: std.builtin.OptimizeMode,

    fn filename(self: BuildInfo) []const u8 {
        var split = std.mem.splitSequence(u8, std.fs.path.basename(self.filepath), ".");
        return split.first();
    }
};
