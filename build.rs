use std::{env, path::PathBuf, process::Command};

use bindgen::callbacks::{EnumVariantValue, ParseCallbacks};
use heck::ToUpperCamelCase;

fn ninja_available() -> bool {
    Command::new("ninja").arg("--version").spawn().is_ok()
}

fn msvc_cmake_tools_available() -> bool {
    Command::new("cmake").arg("--version").spawn().is_ok() && ninja_available()
}

fn get_tool_paths_msvc(compiler: &cc::Tool) -> Option<(PathBuf, PathBuf)> {
    // If tools are already available, don't need to find them
    if msvc_cmake_tools_available() {
        return None;
    }

    let target = env::var("TARGET").unwrap();
    let devenv = cc::windows_registry::find_tool(target.as_str(), "devenv");
    let tool_root = devenv.map_or_else(
        || {
            // if devenv (i.e. Visual Studio) was not found, assume compiler is
            // from standalone Build Tools and look there instead.
            let tools_name = std::ffi::OsStr::new("BuildTools");
            let compiler_path = compiler.path().to_path_buf();
            compiler_path
                .iter()
                .find(|x| *x == tools_name)
                .expect("Failed to find devenv or Build Tools");
            compiler_path
                .iter()
                .take_while(|x| *x != tools_name)
                .collect::<PathBuf>()
                .join(tools_name)
                .join(r"Common7\IDE")
        },
        |devenv_tool| devenv_tool.path().parent().unwrap().to_path_buf(),
    );
    let cmake_pkg_dir = tool_root.join(r"CommonExtensions\Microsoft\CMake");
    let cmake_path = cmake_pkg_dir.join(r"CMake\bin\cmake.exe");
    let ninja_path = cmake_pkg_dir.join(r"Ninja\ninja.exe");

    assert!(cmake_path.is_file(), "missing cmake");
    assert!(ninja_path.is_file(), "missing ninja");

    Some((cmake_path, ninja_path))
}

fn build_with_cmake() {
    let current_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let uc_dir = current_dir;
    let compiler = cc::Build::new().get_compiler();

    // Initialize configuration
    let mut config = cmake::Config::new(uc_dir);

    // Check for tools and set up configuration
    let has_ninja = if compiler.is_like_msvc() {
        // MSVC-specific setup
        if let Some((cmake_path, ninja_path)) = get_tool_paths_msvc(&compiler) {
            // Tell Cargo where to find the tools instead of modifying PATH
            println!("cargo:rustc-env=CMAKE_PATH={}", cmake_path.display());
            println!("cargo:rustc-env=NINJA_PATH={}", ninja_path.display());

            // Set cmake path for the cmake crate
            config.define("CMAKE_PROGRAM", cmake_path.to_str().unwrap());
        }
        true
    } else {
        // Non-MSVC setup
        ninja_available()
    };

    // Configure build generator
    if has_ninja {
        config.generator("Ninja");
    }

    let mut archs = String::new();

    if std::env::var("CARGO_FEATURE_ARCH_X86").is_ok() {
        archs.push_str("x86;");
    }
    if std::env::var("CARGO_FEATURE_ARCH_ARM").is_ok() {
        archs.push_str("arm;");
    }
    if std::env::var("CARGO_FEATURE_ARCH_AARCH64").is_ok() {
        archs.push_str("aarch64;");
    }
    if std::env::var("CARGO_FEATURE_ARCH_RISCV").is_ok() {
        archs.push_str("riscv;");
    }
    if std::env::var("CARGO_FEATURE_ARCH_MIPS").is_ok() {
        archs.push_str("mips;");
    }
    if std::env::var("CARGO_FEATURE_ARCH_SPARC").is_ok() {
        archs.push_str("sparc;");
    }
    if std::env::var("CARGO_FEATURE_ARCH_M68K").is_ok() {
        archs.push_str("m68k;");
    }
    if std::env::var("CARGO_FEATURE_ARCH_PPC").is_ok() {
        archs.push_str("ppc;");
    }
    if std::env::var("CARGO_FEATURE_ARCH_S390X").is_ok() {
        archs.push_str("s390x;");
    }
    if std::env::var("CARGO_FEATURE_ARCH_TRICORE").is_ok() {
        archs.push_str("tricore;");
    }

    if !archs.is_empty() {
        archs.pop();
    }

    if config.get_profile() == "Debug" {
        config.define("UNICORN_LOGGING", "ON");
    }

    let dst = config
        .define("UNICORN_BUILD_TESTS", "OFF")
        .define("UNICORN_INSTALL", "ON")
        .define("UNICORN_ARCH", archs)
        .build();

    println!(
        "cargo:rustc-link-search=native={}",
        dst.join("lib").display()
    );
    // rhel
    println!(
        "cargo:rustc-link-search=native={}",
        dst.join("lib64").display()
    );

    // Lazymio(@wtdcode): Dynamic link may break. See: https://github.com/rust-lang/cargo/issues/5077
    if cfg!(feature = "dynamic_linkage") {
        if compiler.is_like_msvc() {
            println!("cargo:rustc-link-lib=dylib=unicorn-import");
        } else {
            println!("cargo:rustc-link-lib=dylib=unicorn");
        }
    } else {
        println!("cargo:rustc-link-lib=static=unicorn");
    }
    if !compiler.is_like_msvc() {
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=m");
    }
}

fn watch_source_files() {
    let current_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let project_root = std::path::Path::new(&current_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    println!(
        "cargo:rerun-if-changed={}",
        project_root.join("uc.c").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        project_root.join("list.c").display()
    );

    // Directories to watch for changes
    let watch_dirs = vec!["qemu", "include", "bindings", "glib_compat"];

    let watch_extensions = vec![".c", ".h"];

    for dir in watch_dirs {
        let dir_path = project_root.join(dir);
        if dir_path.exists() {
            register_dir_files(&dir_path, &watch_extensions);
        }
    }
}

fn register_dir_files(dir: &std::path::Path, extensions: &[&str]) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                register_dir_files(&path, extensions);
            } else if let Some(ext) = path.extension() {
                if extensions
                    .iter()
                    .any(|&e| e == format!(".{}", ext.to_string_lossy()))
                {
                    println!("cargo:rerun-if-changed={}", path.display());
                }
            }
        }
    }
}

#[derive(Debug)]
struct Renamer;

impl ParseCallbacks for Renamer {
    fn item_name(&self, original_item_name: &str) -> Option<String> {
        // Special case for error type
        if original_item_name == "uc_err" {
            return Some(String::from("uc_error"));
        }

        if original_item_name.contains("_cpu_") {
            return original_item_name
                .strip_prefix("uc_cpu_")
                .map(|suffix| format!("{}CpuModel", suffix.to_upper_camel_case()));
        }

        if original_item_name.ends_with("_reg") {
            return original_item_name
                .strip_prefix("uc_")
                .and_then(|suffix| suffix.strip_suffix("_reg"))
                .map(|suffix| format!("Register{}", suffix.replace('_', "").to_uppercase()));
        }

        if original_item_name.ends_with("_insn") {
            return original_item_name
                .strip_prefix("uc_")
                .and_then(|suffix| suffix.strip_suffix("_insn"))
                .map(|suffix| format!("{}Insn", suffix.to_upper_camel_case()));
        }

        if original_item_name.contains("_mode_") {
            return original_item_name
                .strip_prefix("uc_mode_")
                .map(|suffix| format!("{}Mode", suffix.to_upper_camel_case()));
        }

        // Map various specific types to more idiomatic Rust names
        match original_item_name {
            "uc_query_type" => Some(String::from("Query")),
            "uc_tlb_type" => Some(String::from("TlbType")),
            "uc_mem_type" => Some(String::from("MemType")),
            "uc_tb" => Some(String::from("TranslationBlock")),
            "uc_arch" => Some(String::from("Arch")),
            "uc_mode" => Some(String::from("Mode")),
            "uc_mem_region" => Some(String::from("MemRegion")),
            "uc_prot" => Some(String::from("Prot")),
            "uc_hook_type" => Some(String::from("HookType")),
            "uc_tlb_entry" => Some(String::from("TlbEntry")),
            "uc_control_type" => Some(String::from("ControlType")),
            "uc_context_content" => Some(String::from("ContextMode")),
            "uc_tcg_op_code" => Some(String::from("TcgOpCode")),
            "uc_tcg_op_flag" => Some(String::from("TcgOpFlag")),
            _ => None,
        }
    }

    fn enum_variant_name(
        &self,
        enum_name: Option<&str>,
        original_variant_name: &str,
        _variant_value: EnumVariantValue,
    ) -> Option<String> {
        if let Some(enum_name) = enum_name {
            if enum_name.starts_with("enum uc_") {
                // Prefix to strip from enum variant names
                let prefix = match enum_name.strip_prefix("enum uc_").unwrap() {
                    "query_type" => "UC_QUERY",
                    "tlb_type" => "UC_TLB",
                    "control_type" => "UC_CTL",
                    "context_content" => "UC_CTL_CONTEXT",
                    "err" => "UC_ERR",
                    "mem_type" | "mem_region" => "UC_MEM",
                    "arch" => "UC_ARCH",
                    "mode" => "UC_MODE",
                    "prot" => "UC_PROT",
                    "hook_type" => "UC_HOOK",
                    "x86_insn" => "UC_X86_INS",
                    "tcg_op_code" => "UC_TCG_OP",
                    "tcg_op_flag" => "UC_TCG_OP_FLAG",
                    other => format!("UC_{}", other.to_uppercase()).leak(),
                }
                .to_string()
                    + "_";

                // Strip prefix
                let mut fixed = original_variant_name
                    .strip_prefix(&prefix)
                    .map(str::to_uppercase);

                // Special handling for numeric register names in PPC and MIPS
                if (enum_name == "enum uc_ppc_reg" || enum_name == "enum uc_mips_reg")
                    && fixed.as_ref().is_some_and(|s| s.parse::<u32>().is_ok())
                {
                    fixed = fixed.map(|s| format!("R{s}"));
                }

                // Special handling for CPU variants that start with a number
                if enum_name.contains("cpu")
                    && fixed
                        .as_ref()
                        .is_some_and(|s| s.chars().next().unwrap().is_ascii_digit())
                {
                    fixed = fixed.map(|s| format!("Model_{s}"));
                }

                // Special handling for mode values
                if enum_name == "enum uc_mode" {
                    fixed = fixed.map(|s| match s.as_str() {
                        "16" | "32" | "64" => format!("MODE_{s}"),
                        _ => s,
                    });
                }

                return fixed;
            }
        }

        None
    }
}

fn generate_bindings() {
    const HEADER_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/include/unicorn/unicorn.h");

    let bitflag_enums = [
        "uc_hook_type",
        "uc_tcg_op_flag",
        "uc_prot",
        "uc_mode",
        "uc_context_content",
        "uc_control_type",
    ];

    let bindings = bindgen::Builder::default()
        .header(HEADER_PATH)
        .layout_tests(false)
        .allowlist_type("^uc.*")
        .allowlist_function("^uc_.*")
        .allowlist_var("^uc.*")
        .rustified_enum("^uc.*")
        .prepend_enum_name(false)
        .parse_callbacks(Box::new(Renamer))
        .bitfield_enum(bitflag_enums.join("|"))
        .derive_ord(true)
        .derive_eq(true)
        .use_core()
        .generate()
        .expect("Failed to generate bindings");

    let bindings_rs = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("bindings.rs");
    bindings
        .write_to_file(&bindings_rs)
        .unwrap_or_else(|_| panic!("Failed to write bindings into path: {bindings_rs:?}"));
}

fn main() {
    watch_source_files();

    generate_bindings();

    match pkg_config::Config::new()
        .atleast_version("2")
        .cargo_metadata(false)
        .probe("unicorn")
    {
        Ok(lib) => {
            for dir in lib.link_paths {
                println!("cargo:rustc-link-search=native={}", dir.to_str().unwrap());
            }
            if cfg!(feature = "dynamic_linkage") {
                if cc::Build::new().get_compiler().is_like_msvc() {
                    println!("cargo:rustc-link-lib=dylib=unicorn-import");
                } else {
                    println!("cargo:rustc-link-lib=dylib=unicorn");
                }
            } else {
                println!("cargo:rustc-link-arg=-Wl,-allow-multiple-definition");
                println!("cargo:rustc-link-lib=static=unicorn");
                println!("cargo:rustc-link-lib=pthread");
                println!("cargo:rustc-link-lib=m");
            }
        }
        Err(_) => {
            build_with_cmake();
        }
    }
}
