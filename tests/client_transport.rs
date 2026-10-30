//! Tokio transport integration tests.
#![cfg(feature = "tokio")]

/// Transport scenarios and their loopback fixtures.
#[path = "client_transport/cases.rs"]
mod cases;
