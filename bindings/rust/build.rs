#[cfg(feature = "build")]
fn main() {
    use std::env;
    use std::path::PathBuf;

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let unicorn_dir = manifest_dir.parent().unwrap().parent().unwrap();
    println!("cargo:rerun-if-changed={}", unicorn_dir.display());

    let install_dir = cmake::Config::new(unicorn_dir)
        .define("UNICORN_BUILD_SHARED", "OFF")
        .build();
    env::remove_var("PKG_CONFIG_PATH");
    env::set_var(
        "PKG_CONFIG_LIBDIR",
        install_dir.join("lib").join("pkgconfig"),
    );
    pkg_config::Config::new()
        .statik(true)
        .probe("unicorn")
        .unwrap();
}

#[cfg(feature = "system")]
fn main() {
    pkg_config::probe_library("unicorn").unwrap();
}
