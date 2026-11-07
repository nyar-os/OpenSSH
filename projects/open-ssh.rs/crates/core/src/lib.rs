#![deny(missing_debug_implementations, missing_copy_implementations)]
#![warn(missing_docs, rustdoc::missing_crate_level_docs)]
#![doc = include_str!("../readme.md")]

/// Stable capability ids and the audit summary vocabulary.
pub mod audit;
/// Capability states, stable error codes, and the structured error type.
pub mod errors;
/// Host platform descriptor and the capability report.
pub mod platform;

pub use errors::{CapabilityState, Error, ErrorCode, Result};
