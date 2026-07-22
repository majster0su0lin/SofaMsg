/// UniFFI build script.
///
/// This reads `src/sofamsg.udl` and generates Rust scaffolding code
/// that maps our exported functions/types to the C ABI calling
/// convention expected by the Kotlin/Swift bindings.
fn main() {
    uniffi::generate_scaffolding("src/sofamsg.udl")
        .expect("UniFFI scaffolding generation failed — check src/sofamsg.udl for syntax errors");
}
