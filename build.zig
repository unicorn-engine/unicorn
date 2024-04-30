//! License: GNU GENERAL PUBLIC LICENSE Version 2

const std = @import("std");
const MIN_ZIG_VERSION: []const u8 = "0.12.0";
const MIN_ZIG_VERSION_ERR_MSG = "Please! Update zig toolchain to >= v" ++ MIN_ZIG_VERSION;

const SampleFileTypes = enum {
    c,
    cpp,
    zig,
};

const SampleDescripton = struct {
    file_type: SampleFileTypes,
    root_file_path: []const u8,
};

/// Create a module for the Zig Bindings
///
/// This will also get exported as a library that other zig projects can use
/// as a dependency via the zig build system.
fn create_unicorn_sys(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    const unicorn_sys = b.addModule("unicorn-sys", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("bindings/zig/unicorn/unicorn.zig"),
    });

    // link libc
    unicorn_sys.link_libc = true;

    // we need the c header for the zig-bindings
    unicorn_sys.addIncludePath(b.path("include"));
    unicorn_sys.addLibraryPath(b.path("build"));

    // Linking to the Unicorn library
    if (target.result.abi == .msvc and target.result.os.tag == .windows) {
        unicorn_sys.linkSystemLibrary("unicorn.dll", .{});
    } else {
        unicorn_sys.linkSystemLibrary("unicorn", .{});
    }

    return unicorn_sys;
}

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    if (comptime !checkVersion())
        @compileError(MIN_ZIG_VERSION_ERR_MSG);

    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    // Give the user the options to perform the cmake build in parallel or not
    // (eg. ci on macos will fail if parallel is enabled)
    //
    // flag: -Dparallel=true/false
    const parallel_cmake = b.option(bool, "parallel", "Enable parallel cmake build") orelse true;

    // flag: -DSamples=True/False
    const samples = b.option(bool, "Samples", "Build all Samples [default: true]") orelse true;

    const sample_bins = [_]SampleDescripton{
        .{ .file_type = .zig, .root_file_path = "bindings/zig/sample/sample_riscv_zig.zig" },
        .{ .file_type = .c, .root_file_path = "samples/sample_arm.c" },
        .{ .file_type = .c, .root_file_path = "samples/sample_arm64.c" },
        .{ .file_type = .c, .root_file_path = "samples/sample_ctl.c" },
        .{ .file_type = .c, .root_file_path = "samples/sample_batch_reg.c" },
        .{ .file_type = .c, .root_file_path = "samples/sample_m68k.c" },
        .{ .file_type = .c, .root_file_path = "samples/sample_riscv.c" },
        .{ .file_type = .c, .root_file_path = "samples/sample_sparc.c" },
        .{ .file_type = .c, .root_file_path = "samples/sample_s390x.c" },
        .{ .file_type = .c, .root_file_path = "samples/shellcode.c" },
        .{ .file_type = .c, .root_file_path = "samples/sample_tricore.c" },
        .{ .file_type = .c, .root_file_path = "samples/sample_x86.c" },
        .{ .file_type = .c, .root_file_path = "samples/sample_x86_32_gdt_and_seg_regs.c" },
    };

    // make a module for Zig Bindings
    const unicorn_sys = create_unicorn_sys(b, target, optimize);

    // Build Samples
    if (samples) {
        for (sample_bins) |sample| {
            const sample_bin = buildExe(b, .{
                .target = target,
                .optimize = optimize,
                .filetype = sample.file_type,
                .filepath = sample.root_file_path,
            });

            // import the unicorn sys module if this is a zig build
            if (sample.file_type == .zig) {
                sample_bin.root_module.addImport("unicorn", unicorn_sys);
            }
        }
    }

    // CMake Build
    const cmake = cmakeBuild(b, parallel_cmake);
    const cmake_step = b.step("cmake", "Run cmake build");
    cmake_step.dependOn(&cmake.step);
}

fn buildExe(b: *std.Build, info: BuildInfo) *std.Build.Step.Compile {
    const target = info.stdTarget();

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
    const exe = b.addExecutable(execonfig);

    if (info.filetype != .zig) {
        exe.addCSourceFile(.{
            .file = .{ .path = info.filepath },
            .flags = &.{
                "-Wall",
                "-Werror",
                "-fno-sanitize=all",
                "-Wshadow",
            },
        });

        // Ensure the C headers are available
        exe.addIncludePath(.{ .path = "include" });

        // Ensure the C library is available
        exe.addLibraryPath(.{ .path = "build" });

        // linking to OS-LibC or static-linking for:
        // Musl(Linux) [e.g: -Dtarget=native-linux-musl]
        // MinGW(Windows) [e.g: -Dtarget=native-windows-gnu (default)]
        if (info.filetype == .cpp and target.abi != .msvc)
            exe.linkLibCpp() // static-linking LLVM-libcxx (all targets) + libC
        else
            exe.linkLibC();

        // Now link the C library
        if (target.abi == .msvc and target.os.tag == .windows) {
            exe.linkSystemLibrary("unicorn.dll");
        } else exe.linkSystemLibrary("unicorn");
    }

    // Linking to the Unicorn library
    if (target.abi == .msvc and target.os.tag == .windows) {
        exe.want_lto = false;
    }

    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
    b.installArtifact(exe);

    // This *creates* a RunStep in the build graph, to be executed when another
    // step is evaluated that depends on it. The next line below will establish
    // such a dependency.
    const run_cmd = b.addRunArtifact(exe);

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

    return exe;
}

const PARALLEL_CMAKE_COMMAND = [_][]const u8{
    "cmake",
    "--build",
    "build",
    "--config",
    "release",
    "--parallel",
};

const SINGLE_CMAKE_COMMAND = [_][]const u8{
    "cmake",
    "--build",
    "build",
    "--config",
    "release",
};
fn cmakeBuild(b: *std.Build, parallel_cmake: bool) *std.Build.Step.Run {
    const preconf = b.addSystemCommand(&.{
        "cmake",
        "-B",
        "build",
        "-DZIG_BUILD=ON",
        "-DUNICORN_BUILD_TESTS=OFF",
        "-DUNICORN_INSTALL=OFF",
        "-DCMAKE_BUILD_TYPE=Release",
    });

    // build in parallel if requested
    const cmakebuild = b.addSystemCommand(blk: {
        if (parallel_cmake) {
            break :blk &PARALLEL_CMAKE_COMMAND;
        } else {
            break :blk &SINGLE_CMAKE_COMMAND;
        }
    });
    cmakebuild.step.dependOn(&preconf.step);
    return cmakebuild;
}

// ensures the currently in-use zig version is at least the minimum required
fn checkVersion() bool {
    const builtin = @import("builtin");
    if (!@hasDecl(builtin, "zig_version")) {
        return false;
    }

    const needed_version = std.SemanticVersion.parse(MIN_ZIG_VERSION) catch unreachable;
    const version = builtin.zig_version;
    const order = version.order(needed_version);
    return order != .lt;
}

const BuildInfo = struct {
    filepath: []const u8,
    filetype: SampleFileTypes,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,

    fn filename(self: BuildInfo) []const u8 {
        var split = std.mem.splitSequence(u8, std.fs.path.basename(self.filepath), ".");
        return split.first();
    }

    fn stdTarget(self: *const BuildInfo) std.Target {
        return self.target.result;
    }
};
