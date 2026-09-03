//! Compiles `style/main.scss` to `assets/main.css` under this crate's
//! manifest directory, where `asset!("assets/main.css")` in `layout.rs`
//! expects to find it. Crate-relative rather than `OUT_DIR`-relative so the
//! asset's id does not churn with every profile/build-hash — the same
//! contract izlek-web's build script keeps.

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let scss = format!("{manifest_dir}/../../style/main.scss");
    println!("cargo:rerun-if-changed={scss}");

    let css = grass::from_path(&scss, &grass::Options::default())
        .unwrap_or_else(|err| panic!("failed to compile {scss}: {err}"));
    let out_dir = format!("{manifest_dir}/assets");
    std::fs::create_dir_all(&out_dir).expect("failed to create assets/");
    std::fs::write(format!("{out_dir}/main.css"), &css).expect("failed to write assets/main.css");
}
