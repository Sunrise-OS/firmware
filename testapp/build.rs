//! The workspace links every `aarch64-unknown-uefi` image as a boot-service
//! driver, which is what the DXE core is. This one is an application: BDS loads
//! it from the ESP, and firmware treats the two kinds differently (an
//! application's memory is reclaimed when it returns). The later `/subsystem`
//! on the link line is the one lld-link keeps.
fn main() {
    println!("cargo:rustc-link-arg-bins=/subsystem:efi_application");
}
