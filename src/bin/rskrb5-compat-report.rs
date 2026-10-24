#![expect(missing_docs, reason = "lint-migration: upstream baseline at ee9cb04")]
#![cfg_attr(
    doc,
    expect(
        rustdoc::missing_crate_level_docs,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[expect(
    clippy::absolute_paths,
    clippy::print_stdout,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
fn main() {
    print!("{}", rskrb5::evaluation::render_markdown());
}
