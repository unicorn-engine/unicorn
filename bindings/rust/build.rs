use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let unicorn_dir = manifest_dir.parent().unwrap().parent().unwrap();
    println!("cargo:rerun-if-changed={}", unicorn_dir.display());

    let install_dir = cmake::Config::new(unicorn_dir)
        .define("UNICORN_BUILD_SHARED", "OFF")
        .build();
    println!(
        "cargo:rustc-link-search=native={}",
        install_dir.join("lib").display()
    );
    println!("cargo:rustc-link-lib=static=unicorn");
}
