use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let vendor = manifest
        .join("../../vendor/euicc-rsp")
        .canonicalize()
        .expect("vendor/euicc-rsp is missing -- did the submodule get checked out?");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());

    // euicc-rsp's own Makefile builds librsp.a, generates the asn1c codec
    // into dist/, and builds the vendored mbedTLS. Driving it beats
    // reimplementing it: the codec generation alone has an asn1c version
    // floor and a skeleton-directory dance that the Makefile already
    // knows about.
    let st = Command::new("make")
        .current_dir(&vendor)
        .status()
        .expect("could not run make -- is it on PATH?");
    assert!(st.success(), "euicc-rsp's make failed");

    // dist/ holds one object file per generated ASN.1 type -- several
    // hundred of them. Bundle them into a single archive rather than
    // emitting a link argument each.
    let mut objs: Vec<PathBuf> = fs::read_dir(vendor.join("dist"))
        .expect("dist/ is missing -- did asn1c run?")
        .filter_map(|e| {
            let p = e.ok()?.path();
            (p.extension().and_then(|x| x.to_str()) == Some("o")).then_some(p)
        })
        .collect();
    assert!(!objs.is_empty(), "no dist/*.o to bundle");
    objs.sort(); // so the archive is reproducible

    let dist_a = out.join("libdist.a");
    let _ = fs::remove_file(&dist_a);
    let st = Command::new("ar")
        .arg("rcs")
        .arg(&dist_a)
        .args(&objs)
        .status()
        .expect("could not run ar");
    assert!(st.success(), "ar failed to build libdist.a");

    // Order matters: librsp refers to the codec and to mbedTLS, so it is
    // named before them.
    println!("cargo:rustc-link-search=native={}", vendor.display());
    println!("cargo:rustc-link-search=native={}", out.display());
    println!(
        "cargo:rustc-link-search=native={}",
        vendor.join("vendor/mbedtls/library").display()
    );
    println!("cargo:rustc-link-lib=static=rsp");
    println!("cargo:rustc-link-lib=static=dist");
    println!("cargo:rustc-link-lib=static=mbedx509");
    println!("cargo:rustc-link-lib=static=mbedcrypto");

    let header = vendor.join("include/rsp.h");
    println!("cargo:rerun-if-changed={}", header.display());
    bindgen::Builder::default()
        .header(header.to_str().unwrap())
        .allowlist_function("rsp_.*")
        .allowlist_type("rsp_.*")
        .generate()
        .expect("bindgen failed")
        .write_to_file(out.join("bindings.rs"))
        .expect("could not write bindings.rs");
}
