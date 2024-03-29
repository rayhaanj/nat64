extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .rust_target(bindgen::RustTarget::Stable_1_21)
        .derive_default(true)
        .rustfmt_bindings(true)
        .generate()
        .expect("failed to generate bindings");
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("failed to write bindings");

}
