use cmake;

// To get ninja fetch from here and drop .exe in your PATH:
// https://github.com/ninja-build/ninja/releases
fn main() {
    let mut config = cmake::Config::new("../../.");
    let target = config.generator("Ninja").build_target("unicorn");
    let mut dst = target.build();
    dst.push("build");
    println!("cargo:rustc-link-search=native={}", dst.display());
    println!("cargo:rustc-link-lib=unicorn");
}
