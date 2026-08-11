use std::ffi::CStr;

/// The whole point of this crate: that the C library builds, links, and
/// answers. `rsp_version` is the cheapest question it can be asked.
#[test]
fn the_library_links_and_answers() {
    let raw = unsafe { rsp_sys::rsp_version() };
    assert!(!raw.is_null(), "rsp_version returned NULL");
    let v = unsafe { CStr::from_ptr(raw) }
        .to_str()
        .expect("the version is UTF-8");
    assert!(!v.is_empty(), "rsp_version returned an empty string");
    println!("euicc-rsp {v}");
}
