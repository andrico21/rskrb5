//! Print the candidate-crate compatibility report as Markdown on standard output.

use std::io::{self, Write as _};

use rskrb5_ng::evaluation::render_markdown;

/// Write the Markdown report to standard output.
///
/// # Errors
///
/// Returns the I/O error when standard output cannot be written.
fn main() -> io::Result<()> {
    io::stdout().lock().write_all(render_markdown().as_bytes())
}
