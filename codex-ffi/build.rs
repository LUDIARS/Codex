//! Generate `include/codex.h` on build. The header is checked into git
//! so downstream SDK projects can depend on a known-good version
//! without needing a Rust toolchain; running `cargo build -p codex-ffi`
//! refreshes it.

use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out = PathBuf::from(&crate_dir).join("include").join("codex.h");
    std::fs::create_dir_all(out.parent().unwrap()).ok();

    let cfg = cbindgen::Config {
        language: cbindgen::Language::C,
        header: Some(
            "/* Codex FFI — auto-generated from codex-ffi/src/lib.rs via cbindgen. */\n\
             /* Do not edit by hand. Regenerate via `cargo build -p codex-ffi`. */"
                .into(),
        ),
        include_guard: Some("CODEX_H".into()),
        cpp_compat: true,
        ..cbindgen::Config::default()
    };

    match cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(cfg)
        .generate()
    {
        Ok(bindings) => {
            bindings.write_to_file(&out);
            println!("cargo:rerun-if-changed=src/lib.rs");
        }
        Err(e) => {
            // Don't fail the build if cbindgen isn't happy — the Rust
            // cdylib is usable without the header. Emit a warning.
            println!("cargo:warning=cbindgen failed: {e}");
        }
    }
}
