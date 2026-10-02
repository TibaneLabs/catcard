//! Put `link.x`, the app memory layout, on the linker's search path, so an app's
//! `-Tlink.x` finds it. A search path from a dependency's build script reaches the final
//! link; a `rustc-link-arg` would not.
fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    println!("cargo:rustc-link-search={dir}");
    println!("cargo:rerun-if-changed=link.x");
}
