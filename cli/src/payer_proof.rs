//! Payer proof re-exports and utilities.
//!
//! This module re-exports the payer proof types from the rust-lightning crate
//! and provides additional utilities for test vector generation.

use thiserror::Error;

/// Errors specific to test vector operations.
#[derive(Debug, Error)]
pub enum TestVectorError {
    #[error("Failed to build offer: {0}")]
    OfferBuild(String),

    #[error("Failed to build invoice: {0}")]
    InvoiceBuild(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Verification failed: {0}")]
    Verification(String),
}
