use bytes::Buf;
use flate2::read::GzDecoder;
use reqwest::header::USER_AGENT;
use std::path::{Path, PathBuf};
use std::{env, process::Command};
use tar::Archive;

fn find_unicorn(unicorn_dir: &Path) -> Option<PathBuf> {
    for entry in std::fs::read_dir(unicorn_dir).ok()? {
        let entry = entry.unwrap();
        let path = entry.path();

        if path.is_dir() && path.file_name()?.to_str()?.contains("unicorn") {
            return Some(path);
        }
    }

    None
}

fn out_dir() -> PathBuf {
    let out_dir = env::var("OUT_DIR").unwrap();
    Path::new(&out_dir).to_path_buf()
}

fn download_unicorn() -> PathBuf {
    // https://docs.github.com/en/rest/reference/repos#download-a-repository-archive-tar
    let pkg_version;
    if let Ok(unicorn_version) = env::var("UNICORN_VERSION") {
        pkg_version = unicorn_version;
    } else {
        pkg_version = env::var("CARGO_PKG_VERSION").unwrap();
    }
    let out_dir = out_dir();
    let client = reqwest::blocking::Client::new();
    let resp = client
        .get(format!(
            "https://api.github.com/repos/unicorn-engine/unicorn/tarball/{}",
            pkg_version
        ))
        .header(USER_AGENT, "unicorn-engine-rust-bindings")
        .send()
        .unwrap()
        .bytes()
        .unwrap();
    let tar = GzDecoder::new(resp.reader());

    let mut archive = Archive::new(tar);
    archive.unpack(&out_dir).unwrap();

    find_unicorn(&out_dir).unwrap()
}

#[allow(clippy::branches_sharing_code)]
fn main() {
    let profile = env::var("PROFILE").unwrap();

    if let Some(unicorn_dir) = find_unicorn(&out_dir()) {
        let rust_build_path = unicorn_dir.join("rust_build");
        println!(
            "cargo:rustc-link-search={}",
            rust_build_path.to_str().unwrap()
        );
        println!(
            "cargo:rustc-link-search={}",
            rust_build_path.join("Debug").to_str().unwrap()
        );
        println!(
            "cargo:rustc-link-search={}",
            rust_build_path.join("Release").to_str().unwrap()
        );
    } else {
        let unicorn_dir = if let Result::Ok(_) = env::var("UNICORN_LOCAL") {
            Path::new("..").join("..")
        } else {
            println!("cargo:warning=Unicorn not found. Downloading...");
            download_unicorn()
        };

        let rust_build_path = unicorn_dir.join("rust_build");

        let mut cmd = Command::new("cmake");

        // We don't use TARGET since we can't cross-build.
        if env::consts::OS == "windows" {
            // Windows
            cmd.current_dir(&unicorn_dir)
                .arg("-B")
                .arg("rust_build")
                .arg("-DUNICORN_BUILD_SHARED=off")
                .arg("-G")
                .arg("Visual Studio 16 2019");

            if profile == "debug" {
                cmd.arg("-DCMAKE_BUILD_TYPE=Debug");
            } else {
                cmd.arg("-DCMAKE_BUILD_TYPE=Release");
            }

            cmd.output()
                .expect("Fail to create build directory on Windows.");

            let mut platform = "x64";
            let mut conf = "Release";
            if std::mem::size_of::<usize>() == 4 {
                platform = "Win32";
            }
            if profile == "debug" {
                conf = "Debug";
            }

            Command::new("msbuild")
                .current_dir(&rust_build_path)
                .arg("unicorn.sln")
                .arg("-m")
                .arg("-p:Platform=".to_owned() + platform)
                .arg("-p:Configuration=".to_owned() + conf)
                .output()
                .expect("Fail to build unicorn on Win32.");
            println!(
                "cargo:rustc-link-search={}",
                rust_build_path.join(conf).to_str().unwrap()
            );
        } else {
            // Most Unix-like systems
            let mut cmd = Command::new("cmake");
            cmd.current_dir(&unicorn_dir)
                .arg("-B")
                .arg("rust_build")
                .arg("-DUNICORN_BUILD_SHARED=off");

            if profile == "debug" {
                cmd.arg("-DCMAKE_BUILD_TYPE=Debug");
            } else {
                cmd.arg("-DCMAKE_BUILD_TYPE=Release");
            }

            cmd.output()
                .expect("Fail to create build directory on *nix.");

            Command::new("make")
                .current_dir(&rust_build_path)
                .arg("-j6")
                .output()
                .expect("Fail to build unicorn on *nix.");

            println!(
                "cargo:rustc-link-search={}",
                rust_build_path.to_str().unwrap()
            );
        }
    }

    // This is a workaround for Unicorn static link since libunicorn.a is also linked again lib*-softmmu.a.
    // Static libs is just a bundle of objects files. The link relation defined in CMakeLists is only
    // valid within the cmake project scope and cmake would help link again sub static libs automatically.
    //
    // Lazymio(@wtdcode): Why do I stick to static link? See: https://github.com/rust-lang/cargo/issues/5077
    println!("cargo:rustc-link-lib=unicorn");
    for arch in [
        "x86_64",
        "arm",
        "armeb",
        "aarch64",
        "aarch64eb",
        "riscv32",
        "riscv64",
        "mips",
        "mipsel",
        "mips64",
        "mips64el",
        "sparc",
        "sparc64",
        "m68k",
        "ppc",
        "ppc64",
    ]
    .iter()
    {
        println!("cargo:rustc-link-lib={}-softmmu", arch);
    }
    println!("cargo:rustc-link-lib=unicorn-common");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src");
}
