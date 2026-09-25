use std::env;
use std::fmt::Write;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let dist = root.join("../../web/dist/management");
    println!("cargo:rerun-if-changed={}", dist.display());

    let mut files = Vec::new();
    collect_files(&dist, &dist, &mut files);
    files.sort();

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("cargo output directory"))
        .join("management_assets.rs");
    let mut generated = String::from("pub static MANAGEMENT_ASSETS: &[(&str, &[u8])] = &[\n");
    for (path, source) in files {
        writeln!(generated, "    ({path:?}, include_bytes!({source:?})),")
            .expect("write generated asset map");
    }
    generated.push_str("];\n");
    fs::write(out, generated).expect("write generated asset map file");
}

fn collect_files(root: &Path, directory: &Path, files: &mut Vec<(String, String)>) {
    for entry in fs::read_dir(directory).expect("read management distribution") {
        let entry = entry.expect("read management distribution entry");
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &path, files);
            continue;
        }

        let relative = path
            .strip_prefix(root)
            .expect("asset is below distribution root")
            .to_string_lossy()
            .replace('\\', "/");
        files.push((relative, path.to_string_lossy().replace('\\', "/")));
    }
}
