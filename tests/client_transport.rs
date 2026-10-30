//! Tokio transport integration tests.
#![cfg(feature = "tokio")]

/// Shared ambient classifier and its own adversarial regression suite.
#[path = "ambient_guard.rs"]
mod ambient_guard;

/// Transport scenarios and their loopback fixtures.
#[path = "client_transport/cases.rs"]
mod cases;
