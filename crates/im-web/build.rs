//! Compiles `style/main.scss` to `assets/main.css` under this crate's
//! manifest directory, where `asset!("assets/main.css")` in `layout.rs`
//! expects to find it. Crate-relative rather than `OUT_DIR`-relative so the
//! asset's id does not churn with every profile/build-hash — the same
//! contract izlek-web's build script keeps.

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rerun-if-changed={manifest_dir}/../../style/main.scss");
    println!("cargo:rerun-if-changed={manifest_dir}/../../style/_ledger.scss");
    let scss = format!("{manifest_dir}/../../style/main.scss");

    let css = grass::from_path(&scss, &grass::Options::default())
        .unwrap_or_else(|err| panic!("failed to compile {scss}: {err}"));
    let out_dir = format!("{manifest_dir}/assets");
    std::fs::create_dir_all(&out_dir).expect("failed to create assets/");
    std::fs::write(format!("{out_dir}/main.css"), &css).expect("failed to write assets/main.css");

    // The commit this binary was built from, served by `/healthz` and
    // asserted against after the deploy restart, so a stale process
    // holding the port cannot pass for this deploy. "dev" locally, where
    // nothing asserts it. The rerun-if-env-changed line is load-bearing:
    // without it a rust-cache hit would ship last deploy's sha.
    let sha = std::env::var("IM_BUILD_SHA").unwrap_or_else(|_| "dev".into());
    println!("cargo:rustc-env=IM_BUILD_SHA={sha}");
    println!("cargo:rerun-if-env-changed=IM_BUILD_SHA");
}
