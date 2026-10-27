//! Source guard for the explicitly audited environment-discovery entry points.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{iter::Peekable, str::Chars};
    use std::{fs, io, path::Path};

    /// Audited functions allowed to read process environment variables.
    const READERS: &[(&str, &str)] = &[
        ("config.rs", "load_from_env"),
        ("config.rs", "load_default"),
        ("config.rs", "load_default_or_parse"),
        ("config.rs", "from_env"),
        ("ccache.rs", "load_from_env"),
        ("ccache.rs", "save_to_env"),
        ("keytab.rs", "load_from_env"),
        ("keytab.rs", "save_to_env"),
        ("keytab.rs", "default_keytab_name"),
        ("client.rs", "with_client_keytab_from_env"),
        ("client.rs", "default_ccache_name"),
        ("client.rs", "default_client_keytab_name"),
    ];

    /// Lexes identifiers and delimiters, ignoring comments and literal contents.
    fn tokens(source: &str) -> Vec<String> {
        let mut chars = source.chars().peekable();
        let mut result = Vec::new();
        while let Some(ch) = chars.next() {
            if ch.is_whitespace() {
                continue;
            }
            if ch == '/' && chars.peek() == Some(&'/') {
                for next in chars.by_ref() {
                    if next == '\n' {
                        break;
                    }
                }
            } else if ch == '/' && chars.peek() == Some(&'*') {
                let _: Option<char> = chars.next();
                let mut depth = 1_usize;
                while let Some(next) = chars.next() {
                    match (next, chars.peek()) {
                        ('/', Some('*')) => {
                            let _: Option<char> = chars.next();
                            depth = depth.saturating_add(1);
                        }
                        ('*', Some('/')) => {
                            let _: Option<char> = chars.next();
                            depth = depth.saturating_sub(1);
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            } else if ch == 'r' && matches!(chars.peek(), Some('#' | '"')) {
                let mut hashes = 0_usize;
                while chars.peek() == Some(&'#') {
                    let _: Option<char> = chars.next();
                    hashes = hashes.saturating_add(1);
                }
                if chars.peek() == Some(&'"') {
                    let _: Option<char> = chars.next();
                    while let Some(next) = chars.next() {
                        if next == '"' {
                            let mut closed = 0_usize;
                            while closed < hashes && chars.peek() == Some(&'#') {
                                let _: Option<char> = chars.next();
                                closed = closed.saturating_add(1);
                            }
                            if closed == hashes {
                                break;
                            }
                        }
                    }
                } else {
                    result.push("r".to_owned());
                }
            } else if ch == '"' {
                skip_quoted(&mut chars);
            } else if ch == '\'' {
                let mut probe = chars.clone();
                if probe.next() == Some('\\') {
                    let _: Option<char> = probe.next();
                }
                if probe.next() == Some('\'') {
                    chars = probe;
                }
            } else if ch.is_alphabetic() || ch == '_' {
                let mut word = ch.to_string();
                while chars
                    .peek()
                    .is_some_and(|next| next.is_alphanumeric() || *next == '_')
                {
                    if let Some(next) = chars.next() {
                        word.push(next);
                    }
                }
                result.push(word);
            } else {
                result.push(ch.to_string());
            }
        }
        result
    }

    /// Skips an ordinary quoted string while respecting escaped quotes.
    fn skip_quoted(chars: &mut Peekable<Chars<'_>>) {
        while let Some(next) = chars.next() {
            match next {
                '\\' => {
                    let _: Option<char> = chars.next();
                }
                '"' => break,
                _ => {}
            }
        }
    }

    /// Reports env-read tokens outside audited functions, including imported aliases.
    fn violations(file: &str, source: &str) -> Vec<String> {
        let words = tokens(source);
        let mut failures = Vec::new();
        let mut scopes = Vec::new();
        let mut function = None;
        let mut test_pending = false;
        let mut test_depth = None;
        for (index, word) in words.iter().enumerate() {
            if word == "cfg"
                && words
                    .get(index.saturating_add(1))
                    .is_some_and(|value| value == "(")
                && words
                    .get(index.saturating_add(2))
                    .is_some_and(|value| value == "test")
                && words
                    .get(index.saturating_add(3))
                    .is_some_and(|value| value == ")")
            {
                test_pending = true;
            }
            if word == "fn" {
                function = words.get(index.saturating_add(1)).cloned();
            }
            if word == "{" {
                scopes.push(function.take());
                if test_pending {
                    test_depth = Some(scopes.len());
                    test_pending = false;
                }
            }
            if word == "}" {
                if test_depth == Some(scopes.len()) {
                    test_depth = None;
                }
                drop(scopes.pop());
            }
            if matches!(word.as_str(), "var" | "var_os") && test_depth.is_none() {
                let owner = scopes.iter().rev().find_map(Option::as_deref);
                if !owner.is_some_and(|name| READERS.contains(&(file, name))) {
                    failures.push(format!(
                        "{file}: {} outside audited constructor",
                        owner.unwrap_or("import/module")
                    ));
                }
            }
        }
        failures
    }

    /// Walks every source module so new modules cannot evade the audit.
    fn inspect(directory: &Path) -> Result<Vec<String>, io::Error> {
        let mut failures = Vec::new();
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if path.is_dir() {
                failures.extend(inspect(&path)?);
                continue;
            }
            if path.extension().is_some_and(|extension| extension == "rs") {
                let source = fs::read_to_string(&path)?;
                failures.extend(violations(
                    &path.file_name().unwrap_or_default().to_string_lossy(),
                    &source,
                ));
            }
        }
        Ok(failures)
    }

    /// Production environment reads must stay within the named discovery API.
    #[test]
    fn production_environment_reads_are_explicit() -> Result<(), io::Error> {
        let failures = inspect(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"))?;
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        Ok(())
    }

    /// Module aliases, renamed function imports and fully qualified calls are rejected.
    #[test]
    fn guard_rejects_aliases_and_imports() {
        for source in [
            "fn hidden() { std::env::var(\"HOME\"); }",
            "use std::env as ambient; fn hidden() { ambient::var_os(\"HOME\"); }",
            "use std::env::var as read; fn hidden() { read(\"HOME\"); }",
            "use std::env::{var_os as read}; fn hidden() { read(\"HOME\"); }",
            "use std as platform; fn hidden() { platform::env::var(\"HOME\"); }",
        ] {
            assert!(!violations("config.rs", source).is_empty(), "{source}");
        }
    }

    /// Test-only reads and text literals do not create production discoveries.
    #[test]
    fn guard_exempts_tests_and_literals() {
        let source = r##"#[cfg(test)] mod tests { fn probe() { std::env::var("HOME"); } }
            fn regular() { let text = r#"env::var(\"HOME\")"#; }
            // env::var("HOME")
        "##;
        assert_eq!(violations("config.rs", source), Vec::<String>::new());
    }
}
