use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=LIBUNICORN");
    if let Ok(libunicorn) = env::var("LIBUNICORN") {
        let libunicorn = PathBuf::from(libunicorn);
        println!(
            "cargo:rustc-link-search=native={}",
            libunicorn.parent().unwrap().display()
        );
        println!("cargo:rustc-link-lib=dylib=unicorn");
    } else {
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
}
