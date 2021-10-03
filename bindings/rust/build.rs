use std::{env, process::Command};

use build_helper::rustc::{link_lib, link_search};

fn main() {
    println!("cargo:rerun-if-changed=unicorn");
    let out_dir = env::var("OUT_DIR").unwrap();
    let unicorn = "libunicorn.a";
    let _ = Command::new("cp")
        .current_dir("../..")
        .arg(&unicorn)
        .arg(&out_dir)
        .status()
        .unwrap();
    link_search(
        Some(build_helper::SearchKind::Native),
        build_helper::out_dir(),
    );
    link_lib(Some(build_helper::LibKind::Static), "unicorn");
}
