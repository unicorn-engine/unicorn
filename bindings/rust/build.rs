fn main() {
    let mut config = cmake::Config::new("../../.");

    #[cfg(target_env = "msvc")]
    if !std::env::var("CMAKE_GENERATOR").is_ok() {
        config.generator("Ninja");
    }

    let target = config.build_target("unicorn");
    let mut dst = target.build();
    dst.push("build");
    println!("cargo:rustc-link-search=native={}", dst.display());
    println!("cargo:rustc-link-lib=unicorn");
}
