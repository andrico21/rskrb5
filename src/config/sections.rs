/// The section a line belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SectionKind {
    /// `[libdefaults]`.
    LibDefaults,
    /// `[realms]`.
    Realms,
    /// `[domain_realm]`.
    DomainRealm,
    /// Any other section, or the text before the first section; its lines are
    /// ignored.
    Unknown,
}

impl SectionKind {
    /// The section a `[name]` header line opens, or `None` when the line is
    /// not a section header.
    fn parse(line: &str) -> Option<Self> {
        let close = line.find(']')?;
        // `close` indexes `line`; the name starts after the stripped `[`.
        let section = line.strip_prefix('[')?.get(..close.checked_sub(1)?)?.trim();
        Some(match section.to_ascii_lowercase().as_str() {
            "libdefaults" => Self::LibDefaults,
            "realms" => Self::Realms,
            "domain_realm" => Self::DomainRealm,
            _ => Self::Unknown,
        })
    }
}

/// Apply the lines collected for one section to `config`.
///
/// # Errors
///
/// Returns the error of the section's own parser for a line it refuses.
fn apply_section(
    config: &mut Config,
    section: SectionKind,
    lines: &[Line],
    enctypes: &mut EnctypeParseState,
) -> Result<(), Error> {
    match section {
        SectionKind::LibDefaults => config.libdefaults.parse_lines(lines, enctypes),
        SectionKind::DomainRealm => parse_domain_realm(&mut config.domain_realm, lines),
        SectionKind::Realms | SectionKind::Unknown => Ok(()),
    }
}

/// `line` up to its first `#` or `;` comment marker.
fn strip_comments(line: &str) -> &str {
    // `split` always yields a first piece: the text before the first marker,
    // or the whole line when it has none.
    line.split(['#', ';']).next().unwrap_or(line)
}

/// Split an assignment line into its trimmed key and value.
///
/// # Errors
///
/// Returns [`Error::InvalidLine`] naming `section` when the line has no `=`.
fn parse_assignment<'line>(
    line: &'line Line,
    section: &'static str,
) -> Result<(&'line str, &'line str), Error> {
    let Some((key, value)) = line.text.split_once('=') else {
        return Err(Error::InvalidLine {
            section,
            line: line.number,
            text: line.text.clone(),
        });
    };
    Ok((key.trim(), value.trim()))
}

/// Record the `[domain_realm]` mappings of `lines`, keyed by the lower-cased
/// domain; a later mapping for the same domain replaces an earlier one.
///
/// # Errors
///
/// Returns [`Error::InvalidLine`] for a line that is not an assignment.
fn parse_domain_realm(
    domain_realm: &mut BTreeMap<String, String>,
    lines: &[Line],
) -> Result<(), Error> {
    for line in lines {
        let (domain, realm) = parse_assignment(line, "domain_realm")?;
        // A repeated domain replaces the earlier mapping; the old value is
        // not needed.
        drop(domain_realm.insert(domain.to_ascii_lowercase(), realm.to_owned()));
    }
    Ok(())
}

/// Parse the `[realms]` section: a sequence of `NAME = { ... }` blocks.
///
/// # Errors
///
/// Returns [`Error::InvalidLine`] for a line that is not an assignment,
/// [`Error::InvalidRealmsSection`] for a block that does not open with `{`,
/// closes a brace it never opened or is never closed, and the
/// [`Realm::parse`] errors of each block.
fn parse_realms(lines: &[Line]) -> Result<Vec<Realm>, Error> {
    let mut blocks: Vec<(String, Vec<Line>)> = Vec::new();
    let mut remaining = lines.iter();

    while let Some(line) = remaining.next() {
        let (name, value) = parse_assignment(line, "realms")?;
        if !value.contains('{') {
            return Err(Error::InvalidRealmsSection(format!(
                "realm block for {name} does not start with '{{'"
            )));
        }

        let mut depth = brace_delta(value);
        if depth < 0_i32 {
            return Err(Error::InvalidRealmsSection(
                "unpaired closing brace".to_owned(),
            ));
        }

        let mut block = Vec::new();

        while depth > 0_i32 {
            let Some(block_line) = remaining.next() else {
                break;
            };
            if depth == 1_i32 && !block_line.text.trim().starts_with('}') {
                block.push(block_line.clone());
            }

            // Saturating: a nesting count past `i32` is no real configuration,
            // and it still reads as "inside the block".
            depth = depth.saturating_add(brace_delta(&block_line.text));
            if depth < 0_i32 {
                return Err(Error::InvalidRealmsSection(
                    "unpaired closing brace".to_owned(),
                ));
            }
        }

        if depth != 0_i32 {
            return Err(Error::InvalidRealmsSection(format!(
                "realm block for {name} is not closed"
            )));
        }

        if let Some((_, relations)) = blocks.iter_mut().find(|(realm, _)| realm == name) {
            relations.extend(block);
        } else {
            blocks.push((name.to_owned(), block));
        }
    }

    blocks
        .into_iter()
        .map(|(name, relations)| Realm::parse(&name, &relations))
        .collect()
}

/// The number of `{` in `value` minus the number of `}`.
fn brace_delta(value: &str) -> i32 {
    // Saturating: a brace count past `i32` is no real configuration line.
    value.chars().fold(0_i32, |delta, ch| match ch {
        '{' => delta.saturating_add(1_i32),
        '}' => delta.saturating_sub(1_i32),
        _ => delta,
    })
}
