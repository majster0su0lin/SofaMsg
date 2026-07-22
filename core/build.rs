fn main() {
    // Tell the linker where to find libsqlcipher.so on Termux.
    // The libsqlite3-sys crate's build script emits `cargo:rustc-link-lib=sqlcipher`
    // but relies on pkg-config for the search path, which doesn't always propagate
    // in Termux's non-standard directory layout.
    if std::env::var("TERMUX_VERSION").is_ok()
        || std::path::Path::new("/data/data/com.termux/files/usr/lib").exists()
    {
        println!("cargo:rustc-link-search=native=/data/data/com.termux/files/usr/lib");
    }
}
