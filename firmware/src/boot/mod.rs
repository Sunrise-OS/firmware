//! Finding, loading, and running the boot image.

pub mod manager;

pub use manager::{load_image, start_image, unload_image};
