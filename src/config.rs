//! Kerberos `krb5.conf` parsing.
//!
//! This module covers the gokrb5-compatible configuration surface needed by
//! later client and service modules: libdefaults, realm host mappings, domain
//! realm lookup, duration parsing, and configured KDC discovery.

use std::collections::BTreeMap;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

const KRB5_CONFIG_ENV: &str = "KRB5_CONFIG";
#[cfg(target_family = "unix")]
const PLATFORM_DEFAULT_CONFIG_PATHS: &[&str] = &["/etc/krb5.conf"];
#[cfg(target_family = "windows")]
const PLATFORM_DEFAULT_CONFIG_PATHS: &[&str] = &["C:\\ProgramData\\MIT\\Kerberos5\\krb5.ini"];
#[cfg(not(any(target_family = "unix", target_family = "windows")))]
const PLATFORM_DEFAULT_CONFIG_PATHS: &[&str] = &[];

const DEFAULT_ENCTYPES: &[&str] = &[
    "aes256-cts-hmac-sha1-96",
    "aes128-cts-hmac-sha1-96",
    "des3-cbc-sha1",
    "arcfour-hmac-md5",
    "camellia256-cts-cmac",
    "camellia128-cts-cmac",
    "des-cbc-crc",
    "des-cbc-md5",
    "des-cbc-md4",
];

const DEFAULT_PREAUTH_TYPES: &[i32] = &[17, 16, 15, 14];

/// The deepest `include` nesting a configuration may reach before parsing fails
/// with [`Error::IncludeTooDeep`].
///
/// MIT's parser recurses without a bound; this one is a deliberate divergence so
/// a pathological configuration cannot nest without limit.
pub const MAX_INCLUDE_DEPTH: usize = 8;

/// The most files one configuration may pull in through `include` and
/// `includedir` before parsing fails with [`Error::IncludeTooMany`].
pub const MAX_INCLUDE_FILES: usize = 64;

/// The most bytes one configuration may pull in through `include` and
/// `includedir` - counted across every included file - before parsing fails with
/// [`Error::IncludeTooLarge`] (1 MiB).
pub const MAX_INCLUDE_BYTES: usize = 1024 * 1024;

/// Parsed Kerberos configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Config {
    /// `[libdefaults]` values.
    pub libdefaults: LibDefaults,
    /// `[realms]` entries in file order.
    pub realms: Vec<Realm>,
    /// `[domain_realm]` mappings keyed by lower-case domain names.
    pub domain_realm: BTreeMap<String, String>,
}

impl Config {
    /// Create a config with MIT/gokrb5-style defaults and no parsed sections.
    pub fn new() -> Self {
        Self {
            libdefaults: LibDefaults::new(),
            realms: Vec::new(),
            domain_realm: BTreeMap::new(),
        }
    }

    /// Create a config with no parsed sections, without reading any
    /// environment variable.
    ///
    /// The environment-free twin of [`Config::new`]: the defaults come from
    /// [`LibDefaults::new_without_env`] instead of [`LibDefaults::new`], which
    /// reads `UID` and `HOME`.
    pub fn new_without_env() -> Self {
        Self {
            libdefaults: LibDefaults::new_without_env(),
            realms: Vec::new(),
            domain_realm: BTreeMap::new(),
        }
    }

    /// Load and parse a `krb5.conf` file.
    ///
    /// The file's canonical path is on the open chain before its own directives
    /// expand, so a configuration that includes itself - under any spelling of
    /// its own name - is [`Error::IncludeCycle`] rather than a recursion that
    /// only runs out of depth.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        let canonical = std::fs::canonicalize(path)?;
        let input = std::fs::read_to_string(path)?;
        Self::parse_with_roots(&input, [canonical])
    }

    /// Load and parse the `krb5.conf` path list named by `KRB5_CONFIG`.
    ///
    /// The environment value is split with the platform path-list separator.
    /// On Unix this matches the colon-separated list used by MIT Kerberos.
    pub fn load_from_env() -> Result<Self, Error> {
        let value = std::env::var_os(KRB5_CONFIG_ENV).ok_or(Error::DefaultConfigName)?;
        Self::load_paths(std::env::split_paths(&value))
    }

    /// Load the default Kerberos configuration.
    ///
    /// `KRB5_CONFIG` takes precedence when set. Otherwise this tries platform
    /// defaults such as `/etc/krb5.conf` on Unix.
    pub fn load_default() -> Result<Self, Error> {
        if std::env::var_os(KRB5_CONFIG_ENV).is_some() {
            return Self::load_from_env();
        }
        Self::load_default_paths(PLATFORM_DEFAULT_CONFIG_PATHS.iter().copied())
    }

    /// Load the default Kerberos configuration or parse an embedded fallback.
    ///
    /// The embedded config is used only when no environment or platform
    /// default config source exists. If a configured file exists but cannot be
    /// read or parsed, that error is returned.
    pub fn load_default_or_parse(embedded_krb5_conf: &str) -> Result<Self, Error> {
        if std::env::var_os(KRB5_CONFIG_ENV).is_some() {
            return Self::load_from_env();
        }
        Self::load_default_or_parse_paths(
            embedded_krb5_conf,
            PLATFORM_DEFAULT_CONFIG_PATHS.iter().copied(),
        )
    }

    /// Load and parse one or more `krb5.conf` files.
    ///
    /// Files are concatenated in iterator order before parsing, preserving the
    /// same section semantics as a single file with repeated sections. Each
    /// file's canonical path is on the open chain before any of that text
    /// expands, so a file the list names that one of its own children includes
    /// is [`Error::IncludeCycle`] rather than a second read of the same file.
    pub fn load_paths<I, P>(paths: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let mut input = String::new();
        let mut loaded = 0usize;
        let mut roots = Vec::new();
        for path in paths {
            let path = path.as_ref();
            if path.as_os_str().is_empty() {
                continue;
            }
            if loaded > 0 {
                input.push('\n');
            }
            let canonical = std::fs::canonicalize(path)?;
            input.push_str(&std::fs::read_to_string(path)?);
            input.push('\n');
            roots.push(canonical);
            loaded += 1;
        }
        if loaded == 0 {
            return Err(Error::EmptyConfigPathList);
        }
        Self::parse_with_roots(&input, roots)
    }

    fn load_default_paths<I, P>(paths: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let paths = existing_default_config_paths(paths);
        if paths.is_empty() {
            return Err(Error::NoDefaultConfig);
        }
        Self::load_paths(paths)
    }

    fn load_default_or_parse_paths<I, P>(embedded_krb5_conf: &str, paths: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        match Self::load_default_paths(paths) {
            Ok(config) => Ok(config),
            Err(Error::NoDefaultConfig) => Self::parse(embedded_krb5_conf),
            Err(error) => Err(error),
        }
    }

    /// Parse a `krb5.conf` string.
    ///
    /// A line beginning with `include <file>` or `includedir <dir>` outside a
    /// `{ ... }` group is expanded before the sections are parsed: the named file
    /// is spliced at the directive site (MIT's `parse_include_file`), or every
    /// file the directory holds whose name MIT's `valid_name` accepts is spliced
    /// in alphanumeric order (`parse_include_dir`). The expansion is bounded by
    /// [`MAX_INCLUDE_DEPTH`], [`MAX_INCLUDE_FILES`] and [`MAX_INCLUDE_BYTES`], and
    /// a cycle, an unreadable file or directory, or a bound that is passed is a
    /// named [`Error`] rather than a skipped directive.
    pub fn parse(input: &str) -> Result<Self, Error> {
        Self::parse_with(input, Self::new)
    }

    /// Parse a `krb5.conf` string without reading any environment variable.
    ///
    /// The environment-free twin of [`Config::parse`]: the same parser, with
    /// the defaults taken from [`Config::new_without_env`]. `parse` reaches
    /// `Config::new` -> `LibDefaults::new` -> `UID`/`HOME`, which is exactly
    /// what a caller that must not read the environment cannot have.
    pub fn parse_without_env(input: &str) -> Result<Self, Error> {
        Self::parse_with(input, Self::new_without_env)
    }

    /// The parser both entry points share: they differ in nothing but the
    /// constructor that seeds the defaults.
    fn parse_with(input: &str, seed: fn() -> Self) -> Result<Self, Error> {
        Self::parse_with_roots_and_seed(input, [], seed)
    }

    /// The parser the string entry point and the two file loaders share: they
    /// differ in nothing but the canonical paths the text came from.
    ///
    /// Those paths go on the open chain before the text they contributed is
    /// expanded, which is what makes the configuration's own files cycle
    /// members: a root that includes itself, and a path-list root a child
    /// includes, are [`Error::IncludeCycle`] like any other re-entered file.
    fn parse_with_roots<I>(input: &str, roots: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = PathBuf>,
    {
        Self::parse_with_roots_and_seed(input, roots, Self::new)
    }

    /// Both axes at once: the canonical paths that root the include chain, and
    /// the constructor that seeds the defaults (the environment-free twins pass
    /// [`Config::new_without_env`]). The string entry point and the two file
    /// loaders share this; nothing else in the parser branches on either.
    fn parse_with_roots_and_seed<I>(
        input: &str,
        roots: I,
        seed: fn() -> Self,
    ) -> Result<Self, Error>
    where
        I: IntoIterator<Item = PathBuf>,
    {
        let input = IncludeExpansion::default()
            .with_roots(roots)
            .expand(input, 0)?;
        let mut config = seed();
        let mut current = SectionKind::Unknown;
        let mut lines = Vec::new();

        for (index, raw) in input.lines().enumerate() {
            let line_number = index + 1;
            let cleaned = strip_comments(raw).trim();
            if cleaned.is_empty() {
                continue;
            }

            if let Some(section) = SectionKind::parse(cleaned) {
                apply_section(&mut config, current, &lines)?;
                current = section;
                lines.clear();
                continue;
            }

            if current != SectionKind::Unknown {
                lines.push(Line {
                    number: line_number,
                    text: cleaned.to_owned(),
                });
            }
        }

        apply_section(&mut config, current, &lines)?;
        Ok(config)
    }

    /// Render a gokrb5-style JSON snapshot of the parsed configuration.
    #[cfg(feature = "serde")]
    pub fn json(&self) -> std::result::Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&ConfigJson::from(self))
    }

    /// Return the configured realm with this name.
    pub fn realm(&self, realm: &str) -> Option<&Realm> {
        self.realms.iter().find(|entry| entry.realm == realm)
    }

    /// Resolve a DNS name to a Kerberos realm using `[domain_realm]`.
    ///
    /// This mirrors gokrb5's lookup order: exact hostname first, then the most
    /// specific dotted suffix mapping.
    pub fn resolve_realm(&self, domain_name: &str) -> Option<&str> {
        let domain_name = domain_name.trim_end_matches('.');
        if let Some(realm) = self.domain_realm.get(domain_name) {
            return Some(realm);
        }

        let parts: Vec<_> = domain_name.split('.').collect();
        for start in 1..parts.len() {
            let suffix = format!(".{}", parts[start..].join("."));
            if let Some(realm) = self.domain_realm.get(&suffix) {
                return Some(realm);
            }
        }
        None
    }

    /// Return KDC hosts configured for a realm.
    ///
    /// DNS lookup is intentionally not performed here; the first port keeps
    /// host configuration deterministic and leaves DNS transport for the Tokio
    /// adapter layer.
    pub fn configured_kdcs(&self, realm: &str) -> Result<&[String], Error> {
        let realm_entry = self
            .realm(realm)
            .ok_or_else(|| Error::NoRealm(realm.to_owned()))?;
        if realm_entry.kdc.is_empty() {
            return Err(Error::NoKdc(realm.to_owned()));
        }
        Ok(&realm_entry.kdc)
    }

    /// Return password-change servers configured for a realm.
    pub fn configured_kpasswd_servers(&self, realm: &str) -> Result<&[String], Error> {
        let realm_entry = self
            .realm(realm)
            .ok_or_else(|| Error::NoRealm(realm.to_owned()))?;
        if realm_entry.kpasswd_server.is_empty() {
            return Err(Error::NoKpasswdServer(realm.to_owned()));
        }
        Ok(&realm_entry.kpasswd_server)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

fn existing_default_config_paths<I, P>(paths: I) -> Vec<PathBuf>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    paths
        .into_iter()
        .map(|path| path.as_ref().to_path_buf())
        .filter(|path| path.is_file())
        .collect()
}

/// `[libdefaults]` configuration values.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct LibDefaults {
    /// Whether weak crypto names are retained before supported enctype
    /// filtering.
    pub allow_weak_crypto: bool,
    /// Whether clients should request canonicalization.
    pub canonicalize: bool,
    /// Credential cache type.
    pub ccache_type: i32,
    /// Accepted clock skew.
    pub clockskew: Duration,
    /// Default credential cache name.
    pub default_ccache_name: String,
    /// Default client keytab path.
    pub default_client_keytab_name: String,
    /// Default service keytab path.
    pub default_keytab_name: String,
    /// Default realm.
    pub default_realm: String,
    /// Preferred TGS enctype names.
    pub default_tgs_enctypes: Vec<String>,
    /// Preferred ticket enctype names.
    pub default_tkt_enctypes: Vec<String>,
    /// Preferred TGS enctype IDs implemented by gokrb5-compatible crypto.
    pub default_tgs_enctype_ids: Vec<i32>,
    /// Preferred ticket enctype IDs implemented by gokrb5-compatible crypto.
    pub default_tkt_enctype_ids: Vec<i32>,
    /// Whether hostnames should be DNS-canonicalized.
    pub dns_canonicalize_hostname: bool,
    /// Whether KDC DNS lookup is enabled.
    pub dns_lookup_kdc: bool,
    /// Whether realm DNS lookup is enabled.
    pub dns_lookup_realm: bool,
    /// Extra local addresses.
    pub extra_addresses: Vec<IpAddr>,
    /// Whether tickets should be forwardable.
    pub forwardable: bool,
    /// Whether acceptor hostname mismatches are ignored.
    pub ignore_acceptor_hostname: bool,
    /// Whether `.k5login` is authoritative.
    pub k5login_authoritative: bool,
    /// `.k5login` directory.
    pub k5login_directory: String,
    /// KDC default options bit string as a 32-bit integer.
    pub kdc_default_options: u32,
    /// KDC time sync setting.
    pub kdc_time_sync: i32,
    /// Whether addresses should be omitted from tickets.
    pub no_addresses: bool,
    /// Permitted enctype names.
    pub permitted_enctypes: Vec<String>,
    /// Permitted enctype IDs implemented by gokrb5-compatible crypto.
    pub permitted_enctype_ids: Vec<i32>,
    /// Preferred preauthentication type IDs.
    pub preferred_preauth_types: Vec<i32>,
    /// Whether tickets should be proxiable.
    pub proxiable: bool,
    /// Whether reverse DNS is enabled.
    pub rdns: bool,
    /// Realm suffix search setting.
    pub realm_try_domains: i32,
    /// Renewable ticket lifetime.
    pub renew_lifetime: Duration,
    /// Safe checksum type.
    pub safe_checksum_type: i32,
    /// Ticket lifetime.
    pub ticket_lifetime: Duration,
    /// UDP preference limit.
    pub udp_preference_limit: i32,
    /// Whether AP-REQ verification failure should be fatal.
    pub verify_ap_req_nofail: bool,
}

impl LibDefaults {
    /// The `UID` the client-keytab default path falls back to when the
    /// variable is unset. Named so the environment-reading constructor and the
    /// environment-free one cannot drift apart.
    const FALLBACK_UID: &'static str = "0";

    /// Create default libdefaults.
    pub fn new() -> Self {
        Self::with_uid_and_home(std::env::var("UID").ok(), std::env::var("HOME").ok())
    }

    /// Create default libdefaults without reading any environment variable.
    ///
    /// Identical to [`LibDefaults::new`] except for the two fields `new()`
    /// derives from the environment, which take the values `new()` produces
    /// when the variable is unset:
    ///
    /// - `default_client_keytab_name` is
    ///   `/usr/local/var/krb5/user/0/client.keytab` (the `UID` fallback);
    /// - `k5login_directory` is the empty string (the `HOME` fallback).
    ///
    /// Every other default is the shared non-env default set, so a caller that
    /// must not read the environment gets one default set rather than a second
    /// divergent one.
    pub fn new_without_env() -> Self {
        Self::with_uid_and_home(None, None)
    }

    /// Create default libdefaults from already-read `UID` and `HOME` values, or
    /// from `None` when they must not be read at all.
    fn with_uid_and_home(uid: Option<String>, home: Option<String>) -> Self {
        let default_enctypes = DEFAULT_ENCTYPES
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        let default_client_keytab_name = format!(
            "/usr/local/var/krb5/user/{}/client.keytab",
            uid.unwrap_or_else(|| Self::FALLBACK_UID.to_owned())
        );
        let mut defaults = Self {
            allow_weak_crypto: false,
            canonicalize: false,
            ccache_type: 4,
            clockskew: Duration::from_secs(300),
            default_ccache_name: String::new(),
            default_client_keytab_name,
            default_keytab_name: "/etc/krb5.keytab".to_owned(),
            default_realm: String::new(),
            default_tgs_enctypes: default_enctypes.clone(),
            default_tkt_enctypes: default_enctypes.clone(),
            default_tgs_enctype_ids: Vec::new(),
            default_tkt_enctype_ids: Vec::new(),
            dns_canonicalize_hostname: true,
            dns_lookup_kdc: false,
            dns_lookup_realm: false,
            extra_addresses: Vec::new(),
            forwardable: false,
            ignore_acceptor_hostname: false,
            k5login_authoritative: false,
            k5login_directory: home.unwrap_or_default(),
            kdc_default_options: 0x0000_0010,
            kdc_time_sync: 1,
            no_addresses: true,
            permitted_enctypes: default_enctypes,
            permitted_enctype_ids: Vec::new(),
            preferred_preauth_types: DEFAULT_PREAUTH_TYPES.to_vec(),
            proxiable: false,
            rdns: true,
            realm_try_domains: -1,
            renew_lifetime: Duration::ZERO,
            safe_checksum_type: 8,
            ticket_lifetime: Duration::from_secs(24 * 60 * 60),
            udp_preference_limit: 1465,
            verify_ap_req_nofail: false,
        };
        defaults.refresh_enctype_ids();
        defaults
    }

    fn parse_lines(&mut self, lines: &[Line]) -> Result<(), Error> {
        for line in lines {
            let (key, value) = parse_assignment(line, "libdefaults")?;
            let key = key.to_ascii_lowercase();
            let key = key.as_str();
            if key.contains("v4_") {
                return Err(Error::UnsupportedDirective(
                    "v4 configurations are not supported".to_owned(),
                ));
            }

            match key {
                "allow_weak_crypto" => self.allow_weak_crypto = parse_boolean(value)?,
                "canonicalize" => self.canonicalize = parse_boolean(value)?,
                "ccache_type" => self.ccache_type = parse_i32(value, line, key)?,
                "clockskew" => self.clockskew = parse_duration(value)?,
                "default_ccache_name" => self.default_ccache_name = value.to_owned(),
                "default_client_keytab_name" => {
                    self.default_client_keytab_name = value.to_owned();
                }
                "default_keytab_name" => self.default_keytab_name = value.to_owned(),
                "default_realm" => self.default_realm = value.to_owned(),
                "default_tgs_enctypes" => self.default_tgs_enctypes = parse_words(value),
                "default_tkt_enctypes" => self.default_tkt_enctypes = parse_words(value),
                "dns_canonicalize_hostname" => {
                    self.dns_canonicalize_hostname = parse_boolean(value)?;
                }
                "dns_lookup_kdc" => self.dns_lookup_kdc = parse_boolean(value)?,
                "dns_lookup_realm" => self.dns_lookup_realm = parse_boolean(value)?,
                "extra_addresses" => self.extra_addresses = parse_ip_addresses(value),
                "forwardable" => self.forwardable = parse_boolean(value)?,
                "ignore_acceptor_hostname" => {
                    self.ignore_acceptor_hostname = parse_boolean(value)?;
                }
                "k5login_authoritative" => {
                    self.k5login_authoritative = parse_boolean(value)?;
                }
                "k5login_directory" => self.k5login_directory = value.to_owned(),
                "kdc_default_options" => {
                    self.kdc_default_options = parse_hex_u32(value, line, key)?
                }
                "kdc_timesync" => self.kdc_time_sync = parse_i32(value, line, key)?,
                "noaddresses" | "no_addresses" => self.no_addresses = parse_boolean(value)?,
                "permitted_enctypes" => self.permitted_enctypes = parse_words(value),
                "preferred_preauth_types" => {
                    self.preferred_preauth_types = parse_i32_list(value, line, key)?;
                }
                "proxiable" => self.proxiable = parse_boolean(value)?,
                "rdns" => self.rdns = parse_boolean(value)?,
                "realm_try_domains" => self.realm_try_domains = parse_i32(value, line, key)?,
                "renew_lifetime" => self.renew_lifetime = parse_duration(value)?,
                "safe_checksum_type" => self.safe_checksum_type = parse_i32(value, line, key)?,
                "ticket_lifetime" => self.ticket_lifetime = parse_duration(value)?,
                "udp_preference_limit" => {
                    self.udp_preference_limit = parse_i32(value, line, key)?;
                }
                "verify_ap_req_nofail" => {
                    self.verify_ap_req_nofail = parse_boolean(value)?;
                }
                _ => {}
            }
        }

        self.refresh_enctype_ids();
        Ok(())
    }

    fn refresh_enctype_ids(&mut self) {
        self.default_tgs_enctype_ids =
            parse_supported_enctype_ids(&self.default_tgs_enctypes, self.allow_weak_crypto);
        self.default_tkt_enctype_ids =
            parse_supported_enctype_ids(&self.default_tkt_enctypes, self.allow_weak_crypto);
        self.permitted_enctype_ids =
            parse_supported_enctype_ids(&self.permitted_enctypes, self.allow_weak_crypto);
    }
}

impl Default for LibDefaults {
    fn default() -> Self {
        Self::new()
    }
}

/// One `[realms]` entry.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Realm {
    /// Realm name.
    pub realm: String,
    /// Administrative server hosts.
    pub admin_server: Vec<String>,
    /// Default DNS domain.
    pub default_domain: String,
    /// KDC hosts.
    pub kdc: Vec<String>,
    /// Password-change server hosts.
    pub kpasswd_server: Vec<String>,
    /// Master KDC hosts.
    pub master_kdc: Vec<String>,
}

impl Realm {
    fn new(realm: String) -> Self {
        Self {
            realm,
            admin_server: Vec::new(),
            default_domain: String::new(),
            kdc: Vec::new(),
            kpasswd_server: Vec::new(),
            master_kdc: Vec::new(),
        }
    }

    fn parse(name: &str, lines: &[Line]) -> Result<Self, Error> {
        let mut realm = Self::new(name.to_owned());
        let mut admin_final = false;
        let mut kdc_final = false;
        let mut kpasswd_final = false;
        let mut master_final = false;

        for line in lines {
            let (key, value) = parse_assignment(line, "realms")?;
            let key = key.to_ascii_lowercase();
            let key = key.as_str();
            if key.contains("v4_") {
                return Err(Error::UnsupportedDirective(
                    "v4 configurations are not supported".to_owned(),
                ));
            }

            match key {
                "admin_server" => {
                    append_until_final(&mut realm.admin_server, value, &mut admin_final);
                }
                "default_domain" => realm.default_domain = value.to_owned(),
                "kdc" => {
                    let value = add_default_port(value, 88);
                    append_until_final(&mut realm.kdc, &value, &mut kdc_final);
                }
                "kpasswd_server" => {
                    append_until_final(&mut realm.kpasswd_server, value, &mut kpasswd_final);
                }
                "master_kdc" => {
                    append_until_final(&mut realm.master_kdc, value, &mut master_final);
                }
                _ => {}
            }
        }

        if realm.kpasswd_server.is_empty() {
            realm.kpasswd_server = realm
                .admin_server
                .iter()
                .map(|admin| {
                    let host = admin.split(':').next().unwrap_or(admin);
                    format!("{host}:464")
                })
                .collect();
        }

        Ok(realm)
    }
}

/// Configuration parsing error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// File loading failed.
    #[error("configuration file could not be read: {0}")]
    Io(#[from] std::io::Error),
    /// The default config path list could not be read from `KRB5_CONFIG`.
    #[error("default configuration path list is not set in KRB5_CONFIG")]
    DefaultConfigName,
    /// A config path list contained no usable paths.
    #[error("configuration path list is empty")]
    EmptyConfigPathList,
    /// No environment or platform-default config file exists.
    #[error("no default Kerberos configuration file found")]
    NoDefaultConfig,
    /// A section line was syntactically invalid.
    #[error("invalid {section} section line {line}: {text}")]
    InvalidLine {
        /// Section name.
        section: &'static str,
        /// One-based line number.
        line: usize,
        /// Line text after comment stripping.
        text: String,
    },
    /// A directive is explicitly unsupported.
    #[error("{0}")]
    UnsupportedDirective(String),
    /// A boolean value was invalid.
    #[error("invalid boolean value: {0}")]
    InvalidBoolean(String),
    /// A duration value was invalid.
    #[error("invalid time duration value: {0}")]
    InvalidDuration(String),
    /// A duration value overflowed.
    #[error("time duration overflow: {0}")]
    DurationOverflow(String),
    /// An integer value was invalid.
    #[error("invalid integer for {key} on line {line}: {value}")]
    InvalidInteger {
        /// Line number.
        line: usize,
        /// Config key.
        key: String,
        /// Config value.
        value: String,
    },
    /// An IP address was invalid.
    #[error("invalid IP address for {key} on line {line}: {value}")]
    InvalidIpAddress {
        /// Line number.
        line: usize,
        /// Config key.
        key: String,
        /// Config value.
        value: String,
    },
    /// The realms section has invalid brace structure.
    #[error("invalid realms section: {0}")]
    InvalidRealmsSection(String),
    /// The requested realm is absent.
    #[error("realm not configured: {0}")]
    NoRealm(String),
    /// The requested realm has no configured KDCs.
    #[error("realm has no configured KDCs: {0}")]
    NoKdc(String),
    /// The requested realm has no configured password-change servers.
    #[error("realm has no configured kpasswd servers: {0}")]
    NoKpasswdServer(String),
    /// Include nesting reached past [`MAX_INCLUDE_DEPTH`].
    #[error("include nesting reached depth {depth}, past the limit of {limit}")]
    IncludeTooDeep {
        /// The depth the parser reached.
        depth: usize,
        /// The documented limit.
        limit: usize,
    },
    /// More files were included than [`MAX_INCLUDE_FILES`] allows.
    #[error("configuration included {count} files, past the limit of {limit}")]
    IncludeTooMany {
        /// The number of files the parser reached.
        count: usize,
        /// The documented limit.
        limit: usize,
    },
    /// Included files carried more bytes than [`MAX_INCLUDE_BYTES`] allows.
    #[error("included configuration reached {bytes} bytes, past the limit of {limit}")]
    IncludeTooLarge {
        /// The number of included bytes the parser read. A single file that
        /// overshoots the limit is read only up to the limit plus one byte, so
        /// this is the limit plus one in that case.
        bytes: usize,
        /// The documented limit.
        limit: usize,
    },
    /// An include chain returned to a file or directory it is already reading.
    #[error("include cycle: {path} is already being read")]
    IncludeCycle {
        /// The file or directory the cycle returned to.
        path: PathBuf,
    },
    /// An `include` directive named a file that could not be read, or that is
    /// not UTF-8 text.
    #[error("include file {path} could not be read: {source}")]
    IncludeFile {
        /// The file the directive named.
        path: PathBuf,
        /// Why it could not be used.
        source: std::io::Error,
    },
    /// An `includedir` directive named a directory that could not be listed.
    #[error("includedir {path} could not be listed: {source}")]
    IncludeDir {
        /// The directory the directive named.
        path: PathBuf,
        /// Why it could not be listed.
        source: std::io::Error,
    },
}

#[derive(Clone, Debug)]
struct Line {
    number: usize,
    text: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SectionKind {
    LibDefaults,
    Realms,
    DomainRealm,
    Unknown,
}

impl SectionKind {
    fn parse(line: &str) -> Option<Self> {
        let close = line.find(']')?;
        let section = line.strip_prefix('[')?.get(..close - 1)?.trim();
        Some(match section.to_ascii_lowercase().as_str() {
            "libdefaults" => Self::LibDefaults,
            "realms" => Self::Realms,
            "domain_realm" => Self::DomainRealm,
            _ => Self::Unknown,
        })
    }
}

fn apply_section(config: &mut Config, section: SectionKind, lines: &[Line]) -> Result<(), Error> {
    match section {
        SectionKind::LibDefaults => config.libdefaults.parse_lines(lines),
        SectionKind::Realms => {
            config.realms = parse_realms(lines)?;
            Ok(())
        }
        SectionKind::DomainRealm => parse_domain_realm(&mut config.domain_realm, lines),
        SectionKind::Unknown => Ok(()),
    }
}

fn strip_comments(line: &str) -> &str {
    let hash = line.find('#');
    let semicolon = line.find(';');
    match (hash, semicolon) {
        (Some(left), Some(right)) => &line[..left.min(right)],
        (Some(index), None) | (None, Some(index)) => &line[..index],
        (None, None) => line,
    }
}

fn parse_assignment<'a>(
    line: &'a Line,
    section: &'static str,
) -> Result<(&'a str, &'a str), Error> {
    let Some((key, value)) = line.text.split_once('=') else {
        return Err(Error::InvalidLine {
            section,
            line: line.number,
            text: line.text.clone(),
        });
    };
    Ok((key.trim(), value.trim()))
}

fn parse_domain_realm(
    domain_realm: &mut BTreeMap<String, String>,
    lines: &[Line],
) -> Result<(), Error> {
    for line in lines {
        let (domain, realm) = parse_assignment(line, "domain_realm")?;
        domain_realm.insert(domain.to_ascii_lowercase(), realm.to_owned());
    }
    Ok(())
}

fn parse_realms(lines: &[Line]) -> Result<Vec<Realm>, Error> {
    let mut realms = Vec::new();
    let mut index = 0;

    while index < lines.len() {
        let line = &lines[index];
        let (name, value) = parse_assignment(line, "realms")?;
        if !value.contains('{') {
            return Err(Error::InvalidRealmsSection(format!(
                "realm block for {name} does not start with '{{'"
            )));
        }

        let mut depth = brace_delta(value);
        if depth < 0 {
            return Err(Error::InvalidRealmsSection(
                "unpaired closing brace".to_owned(),
            ));
        }

        let mut block = Vec::new();
        index += 1;

        while index < lines.len() && depth > 0 {
            let block_line = &lines[index];
            if depth == 1 && !block_line.text.trim().starts_with('}') {
                block.push(block_line.clone());
            }

            depth += brace_delta(&block_line.text);
            if depth < 0 {
                return Err(Error::InvalidRealmsSection(
                    "unpaired closing brace".to_owned(),
                ));
            }
            index += 1;
        }

        if depth != 0 {
            return Err(Error::InvalidRealmsSection(format!(
                "realm block for {name} is not closed"
            )));
        }

        realms.push(Realm::parse(name, &block)?);
    }

    Ok(realms)
}

fn brace_delta(value: &str) -> i32 {
    value.matches('{').count() as i32 - value.matches('}').count() as i32
}

/// Parse a krb5 duration value.
///
/// Supported forms match gokrb5's `parseDuration`: seconds (`100`), unit
/// suffixes (`12h30m15s`), days plus suffixes (`1d12h`), and `h:m[:s]`.
pub fn parse_duration(value: &str) -> Result<Duration, Error> {
    let normalized = value.split_whitespace().collect::<String>();
    if normalized.is_empty() {
        return Err(Error::InvalidDuration(value.to_owned()));
    }

    if let Some((days, rest)) = normalized.split_once('d') {
        let days = days
            .parse::<u64>()
            .map_err(|_| Error::InvalidDuration(value.to_owned()))?;
        let day_seconds = days
            .checked_mul(24 * 60 * 60)
            .ok_or_else(|| Error::DurationOverflow(value.to_owned()))?;
        let mut duration = Duration::from_secs(day_seconds);
        if !rest.is_empty() {
            duration = duration
                .checked_add(parse_unit_duration(rest, value)?)
                .ok_or_else(|| Error::DurationOverflow(value.to_owned()))?;
        }
        return Ok(duration);
    }

    if let Ok(duration) = parse_unit_duration(&normalized, value) {
        return Ok(duration);
    }

    if let Ok(seconds) = normalized.parse::<u64>()
        && seconds > 0
    {
        return Ok(Duration::from_secs(seconds));
    }

    if normalized.contains(':') {
        return parse_colon_duration(&normalized, value);
    }

    Err(Error::InvalidDuration(value.to_owned()))
}

/// Parse a krb5 boolean value.
pub fn parse_boolean(value: &str) -> Result<bool, Error> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "t" | "true" | "y" | "yes" => Ok(true),
        "0" | "f" | "false" | "n" | "no" => Ok(false),
        _ => Err(Error::InvalidBoolean(value.to_owned())),
    }
}

/// Parse enctype names to the subset of IDs implemented by gokrb5-compatible
/// crypto.
pub fn parse_supported_enctype_ids(enctypes: &[String], allow_weak_crypto: bool) -> Vec<i32> {
    enctypes
        .iter()
        .filter(|name| allow_weak_crypto || !is_weak_enctype(name))
        .filter_map(|name| supported_enctype_id(name))
        .collect()
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
struct ConfigJson<'a> {
    #[serde(rename = "LibDefaults")]
    libdefaults: LibDefaultsJson<'a>,
    #[serde(rename = "Realms")]
    realms: Vec<RealmJson<'a>>,
    #[serde(rename = "DomainRealm")]
    domain_realm: &'a BTreeMap<String, String>,
}

#[cfg(feature = "serde")]
impl<'a> From<&'a Config> for ConfigJson<'a> {
    fn from(config: &'a Config) -> Self {
        Self {
            libdefaults: LibDefaultsJson::from(&config.libdefaults),
            realms: config.realms.iter().map(RealmJson::from).collect(),
            domain_realm: &config.domain_realm,
        }
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
struct LibDefaultsJson<'a> {
    #[serde(rename = "AllowWeakCrypto")]
    allow_weak_crypto: bool,
    #[serde(rename = "Canonicalize")]
    canonicalize: bool,
    #[serde(rename = "CCacheType")]
    ccache_type: i32,
    #[serde(rename = "Clockskew")]
    clockskew: u128,
    #[serde(rename = "DefaultCCacheName")]
    default_ccache_name: &'a str,
    #[serde(rename = "DefaultClientKeytabName")]
    default_client_keytab_name: &'a str,
    #[serde(rename = "DefaultKeytabName")]
    default_keytab_name: &'a str,
    #[serde(rename = "DefaultRealm")]
    default_realm: &'a str,
    #[serde(rename = "DefaultTGSEnctypes")]
    default_tgs_enctypes: &'a [String],
    #[serde(rename = "DefaultTktEnctypes")]
    default_tkt_enctypes: &'a [String],
    #[serde(rename = "DefaultTGSEnctypeIDs")]
    default_tgs_enctype_ids: &'a [i32],
    #[serde(rename = "DefaultTktEnctypeIDs")]
    default_tkt_enctype_ids: &'a [i32],
    #[serde(rename = "DNSCanonicalizeHostname")]
    dns_canonicalize_hostname: bool,
    #[serde(rename = "DNSLookupKDC")]
    dns_lookup_kdc: bool,
    #[serde(rename = "DNSLookupRealm")]
    dns_lookup_realm: bool,
    #[serde(rename = "ExtraAddresses")]
    extra_addresses: Option<Vec<String>>,
    #[serde(rename = "Forwardable")]
    forwardable: bool,
    #[serde(rename = "IgnoreAcceptorHostname")]
    ignore_acceptor_hostname: bool,
    #[serde(rename = "K5LoginAuthoritative")]
    k5login_authoritative: bool,
    #[serde(rename = "K5LoginDirectory")]
    k5login_directory: &'a str,
    #[serde(rename = "KDCDefaultOptions")]
    kdc_default_options: KerberosBitStringJson,
    #[serde(rename = "KDCTimeSync")]
    kdc_time_sync: i32,
    #[serde(rename = "NoAddresses")]
    no_addresses: bool,
    #[serde(rename = "PermittedEnctypes")]
    permitted_enctypes: &'a [String],
    #[serde(rename = "PermittedEnctypeIDs")]
    permitted_enctype_ids: &'a [i32],
    #[serde(rename = "PreferredPreauthTypes")]
    preferred_preauth_types: &'a [i32],
    #[serde(rename = "Proxiable")]
    proxiable: bool,
    #[serde(rename = "RDNS")]
    rdns: bool,
    #[serde(rename = "RealmTryDomains")]
    realm_try_domains: i32,
    #[serde(rename = "RenewLifetime")]
    renew_lifetime: u128,
    #[serde(rename = "SafeChecksumType")]
    safe_checksum_type: i32,
    #[serde(rename = "TicketLifetime")]
    ticket_lifetime: u128,
    #[serde(rename = "UDPPreferenceLimit")]
    udp_preference_limit: i32,
    #[serde(rename = "VerifyAPReqNofail")]
    verify_ap_req_nofail: bool,
}

#[cfg(feature = "serde")]
impl<'a> From<&'a LibDefaults> for LibDefaultsJson<'a> {
    fn from(libdefaults: &'a LibDefaults) -> Self {
        Self {
            allow_weak_crypto: libdefaults.allow_weak_crypto,
            canonicalize: libdefaults.canonicalize,
            ccache_type: libdefaults.ccache_type,
            clockskew: duration_nanos(libdefaults.clockskew),
            default_ccache_name: &libdefaults.default_ccache_name,
            default_client_keytab_name: &libdefaults.default_client_keytab_name,
            default_keytab_name: &libdefaults.default_keytab_name,
            default_realm: &libdefaults.default_realm,
            default_tgs_enctypes: &libdefaults.default_tgs_enctypes,
            default_tkt_enctypes: &libdefaults.default_tkt_enctypes,
            default_tgs_enctype_ids: &libdefaults.default_tgs_enctype_ids,
            default_tkt_enctype_ids: &libdefaults.default_tkt_enctype_ids,
            dns_canonicalize_hostname: libdefaults.dns_canonicalize_hostname,
            dns_lookup_kdc: libdefaults.dns_lookup_kdc,
            dns_lookup_realm: libdefaults.dns_lookup_realm,
            extra_addresses: optional_ip_addresses(&libdefaults.extra_addresses),
            forwardable: libdefaults.forwardable,
            ignore_acceptor_hostname: libdefaults.ignore_acceptor_hostname,
            k5login_authoritative: libdefaults.k5login_authoritative,
            k5login_directory: &libdefaults.k5login_directory,
            kdc_default_options: KerberosBitStringJson::from_u32(libdefaults.kdc_default_options),
            kdc_time_sync: libdefaults.kdc_time_sync,
            no_addresses: libdefaults.no_addresses,
            permitted_enctypes: &libdefaults.permitted_enctypes,
            permitted_enctype_ids: &libdefaults.permitted_enctype_ids,
            preferred_preauth_types: &libdefaults.preferred_preauth_types,
            proxiable: libdefaults.proxiable,
            rdns: libdefaults.rdns,
            realm_try_domains: libdefaults.realm_try_domains,
            renew_lifetime: duration_nanos(libdefaults.renew_lifetime),
            safe_checksum_type: libdefaults.safe_checksum_type,
            ticket_lifetime: duration_nanos(libdefaults.ticket_lifetime),
            udp_preference_limit: libdefaults.udp_preference_limit,
            verify_ap_req_nofail: libdefaults.verify_ap_req_nofail,
        }
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
struct RealmJson<'a> {
    #[serde(rename = "Realm")]
    realm: &'a str,
    #[serde(rename = "AdminServer")]
    admin_server: Option<&'a [String]>,
    #[serde(rename = "DefaultDomain")]
    default_domain: &'a str,
    #[serde(rename = "KDC")]
    kdc: Option<&'a [String]>,
    #[serde(rename = "KPasswdServer")]
    kpasswd_server: Option<&'a [String]>,
    #[serde(rename = "MasterKDC")]
    master_kdc: Option<&'a [String]>,
}

#[cfg(feature = "serde")]
impl<'a> From<&'a Realm> for RealmJson<'a> {
    fn from(realm: &'a Realm) -> Self {
        Self {
            realm: &realm.realm,
            admin_server: optional_slice(&realm.admin_server),
            default_domain: &realm.default_domain,
            kdc: optional_slice(&realm.kdc),
            kpasswd_server: optional_slice(&realm.kpasswd_server),
            master_kdc: optional_slice(&realm.master_kdc),
        }
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
struct KerberosBitStringJson {
    #[serde(rename = "Bytes")]
    bytes: String,
    #[serde(rename = "BitLength")]
    bit_length: usize,
}

#[cfg(feature = "serde")]
impl KerberosBitStringJson {
    fn from_u32(value: u32) -> Self {
        Self {
            bytes: base64_standard(&value.to_be_bytes()),
            bit_length: u32::BITS as usize,
        }
    }
}

#[cfg(feature = "serde")]
fn optional_slice<T>(values: &[T]) -> Option<&[T]> {
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

#[cfg(feature = "serde")]
fn optional_ip_addresses(values: &[IpAddr]) -> Option<Vec<String>> {
    if values.is_empty() {
        None
    } else {
        Some(values.iter().map(ToString::to_string).collect())
    }
}

#[cfg(feature = "serde")]
fn duration_nanos(duration: Duration) -> u128 {
    duration.as_nanos()
}

#[cfg(feature = "serde")]
fn base64_standard(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        let value = ((first as u32) << 16) | ((second as u32) << 8) | third as u32;

        output.push(TABLE[((value >> 18) & 0x3f) as usize] as char);
        output.push(TABLE[((value >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            output.push(TABLE[((value >> 6) & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(TABLE[(value & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
    }

    output
}

fn parse_unit_duration(input: &str, original: &str) -> Result<Duration, Error> {
    let mut chars = input.char_indices().peekable();
    let mut duration = Duration::ZERO;
    let mut parsed_any = false;

    while chars.peek().is_some() {
        let start = chars.peek().map_or(0, |(index, _)| *index);
        while matches!(chars.peek(), Some((_, ch)) if ch.is_ascii_digit()) {
            chars.next();
        }
        let number_end = chars.peek().map_or(input.len(), |(index, _)| *index);
        if number_end == start {
            return Err(Error::InvalidDuration(original.to_owned()));
        }
        let number = input[start..number_end]
            .parse::<u64>()
            .map_err(|_| Error::InvalidDuration(original.to_owned()))?;

        let unit_start = number_end;
        while matches!(chars.peek(), Some((_, ch)) if ch.is_ascii_alphabetic()) {
            chars.next();
        }
        let unit_end = chars.peek().map_or(input.len(), |(index, _)| *index);
        let unit = &input[unit_start..unit_end];
        let seconds = match unit {
            "h" => number
                .checked_mul(60 * 60)
                .ok_or_else(|| Error::DurationOverflow(original.to_owned()))?,
            "m" => number
                .checked_mul(60)
                .ok_or_else(|| Error::DurationOverflow(original.to_owned()))?,
            "s" => number,
            _ => return Err(Error::InvalidDuration(original.to_owned())),
        };
        duration = duration
            .checked_add(Duration::from_secs(seconds))
            .ok_or_else(|| Error::DurationOverflow(original.to_owned()))?;
        parsed_any = true;
    }

    if parsed_any {
        Ok(duration)
    } else {
        Err(Error::InvalidDuration(original.to_owned()))
    }
}

fn parse_colon_duration(input: &str, original: &str) -> Result<Duration, Error> {
    let parts = input.split(':').collect::<Vec<_>>();
    if !(2..=3).contains(&parts.len()) {
        return Err(Error::InvalidDuration(original.to_owned()));
    }
    let hours = parts[0]
        .parse::<u64>()
        .map_err(|_| Error::InvalidDuration(original.to_owned()))?;
    let minutes = parts[1]
        .parse::<u64>()
        .map_err(|_| Error::InvalidDuration(original.to_owned()))?;
    let seconds = if let Some(value) = parts.get(2) {
        value
            .parse::<u64>()
            .map_err(|_| Error::InvalidDuration(original.to_owned()))?
    } else {
        0
    };

    let total = hours
        .checked_mul(60 * 60)
        .and_then(|value| value.checked_add(minutes.checked_mul(60)?))
        .and_then(|value| value.checked_add(seconds))
        .ok_or_else(|| Error::DurationOverflow(original.to_owned()))?;
    Ok(Duration::from_secs(total))
}

fn parse_i32(value: &str, line: &Line, key: &str) -> Result<i32, Error> {
    value.parse().map_err(|_| invalid_integer(value, line, key))
}

fn parse_i32_list(value: &str, line: &Line, key: &str) -> Result<Vec<i32>, Error> {
    value
        .split([',', ' ', '\t'])
        .filter(|part| !part.trim().is_empty())
        .map(|part| parse_i32(part.trim(), line, key))
        .collect()
}

fn parse_hex_u32(value: &str, line: &Line, key: &str) -> Result<u32, Error> {
    let value = value.trim().trim_start_matches("0x");
    u32::from_str_radix(value, 16).map_err(|_| invalid_integer(value, line, key))
}

fn invalid_integer(value: &str, line: &Line, key: &str) -> Error {
    Error::InvalidInteger {
        line: line.number,
        key: key.to_owned(),
        value: value.to_owned(),
    }
}

fn parse_ip_addresses(value: &str) -> Vec<IpAddr> {
    value
        .split(',')
        .filter_map(|part| part.trim().parse().ok())
        .collect()
}

fn parse_words(value: &str) -> Vec<String> {
    value
        .split_whitespace()
        .map(|value| value.to_owned())
        .collect()
}

fn add_default_port(value: &str, port: u16) -> String {
    let trimmed = value.trim();
    let final_marker = trimmed.ends_with('*');
    let host = trimmed.trim_end_matches('*').trim();
    if host.contains(':') {
        if final_marker {
            format!("{host}*")
        } else {
            host.to_owned()
        }
    } else if final_marker {
        format!("{host}:{port}*")
    } else {
        format!("{host}:{port}")
    }
}

fn append_until_final(values: &mut Vec<String>, value: &str, final_seen: &mut bool) {
    if *final_seen {
        return;
    }

    let mut value = value.trim();
    if let Some(stripped) = value.strip_suffix('*') {
        *final_seen = true;
        value = stripped.trim_end();
    }
    values.push(value.to_owned());
}

fn supported_enctype_id(value: &str) -> Option<i32> {
    Some(match value.to_ascii_lowercase().as_str() {
        "aes128-cts-hmac-sha1-96" | "aes128-cts" | "aes128-sha1" => 17,
        "aes256-cts-hmac-sha1-96" | "aes256-cts" | "aes256-sha1" => 18,
        "aes128-cts-hmac-sha256-128" | "aes128-sha2" => 19,
        "aes256-cts-hmac-sha384-192" | "aes256-sha2" => 20,
        "des3-cbc-sha1-kd" => 16,
        "arcfour-hmac" | "rc4-hmac" | "arcfour-hmac-md5" => 23,
        _ => return None,
    })
}

fn is_weak_enctype(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "des-cbc-crc"
            | "des-cbc-md4"
            | "des-cbc-md5"
            | "des-cbc-raw"
            | "des3-cbc-raw"
            | "des-hmac-sha1"
            | "arcfour-hmac-exp"
            | "rc4-hmac-exp"
            | "arcfour-hmac-md5-exp"
            | "des"
    )
}

/// One `include`/`includedir` directive, split from its argument.
#[derive(Clone, Copy, Debug)]
enum IncludeDirective<'a> {
    /// `include <file>`: splice one file.
    File(&'a str),
    /// `includedir <dir>`: splice every file MIT's filter accepts, in
    /// alphanumeric order.
    Directory(&'a str),
}

impl<'a> IncludeDirective<'a> {
    /// The directive a line carries, or `None` when it carries neither.
    ///
    /// Recognized as the first token of the line - which is where MIT's
    /// `krb5.conf` documentation places them ("at the beginning of a line") and
    /// where `prof_parse.c:282-291` tests for them. MIT requires the keyword at
    /// column 0; leading whitespace is accepted here too, because a line this
    /// parser does not recognize at the top level is skipped silently, and a
    /// directive must never be ignored silently.
    fn parse(line: &'a str) -> Option<Self> {
        // `includedir` first: `include` is a prefix of it.
        if let Some(rest) = line.strip_prefix("includedir")
            && starts_with_whitespace(rest)
        {
            return Some(Self::Directory(rest.trim()));
        }
        let rest = line.strip_prefix("include")?;
        if starts_with_whitespace(rest) {
            return Some(Self::File(rest.trim()));
        }
        None
    }
}

/// Whether `text` begins with whitespace (and so the keyword before it was a
/// whole token).
fn starts_with_whitespace(text: &str) -> bool {
    text.chars().next().is_some_and(char::is_whitespace)
}

/// Whether `name` is one an `includedir` accepts, per MIT's `valid_name`
/// (`krb5-1.21-final`, `src/util/profile/prof_parse.c:224-243`): dotfiles -
/// "editor or filesystem artifacts" - are skipped, a name ending in `.conf` is
/// included, and so is a name made only of alphanumeric characters, dashes and
/// underscores. Like MIT's, it works on the name's bytes.
fn includedir_name_is_valid(name: &[u8]) -> bool {
    if name.starts_with(b".") {
        return false;
    }
    if name.len() >= 5 && name.ends_with(b".conf") {
        return true;
    }
    !name.is_empty()
        && name
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_')
}

/// The `include`/`includedir` budget one parse runs under, and the files and
/// directories whose directives it is expanding right now.
///
/// MIT's parser has neither: it recurses on whatever the configuration names.
/// The caps ([`MAX_INCLUDE_DEPTH`], [`MAX_INCLUDE_FILES`], [`MAX_INCLUDE_BYTES`])
/// and the cycle check on canonical paths are a deliberate divergence from MIT.
#[derive(Default)]
struct IncludeExpansion {
    /// Canonical paths of the files and directories being expanded, outermost
    /// first: the cycle check is a membership test on this chain, so a file - or
    /// a directory reached again through a symlink - that is re-entered by one
    /// of its own descendants is a named [`Error::IncludeCycle`] rather than
    /// unbounded recursion. The configuration's own top-level files are on it
    /// before the first directive expands ([`Self::with_roots`]), so a root that
    /// includes itself is a cycle too.
    open: Vec<PathBuf>,
    /// How many files the directives have included so far.
    files: usize,
    /// How many bytes of included content have been read so far.
    bytes: usize,
}

impl IncludeExpansion {
    /// The same expansion, with the canonical paths the configuration's own
    /// text came from already on the open chain.
    ///
    /// A caller that read its text from files hands them over; a caller parsing
    /// a string hands over nothing, because a string has no path to re-enter.
    fn with_roots<I>(mut self, roots: I) -> Self
    where
        I: IntoIterator<Item = PathBuf>,
    {
        self.open.extend(roots);
        self
    }

    /// Replace every directive in `input` with what it names, recursively.
    ///
    /// `depth` is the include depth of the text itself: the configuration a
    /// caller handed over is depth 0, and each `include` adds one. A directive
    /// inside a `{ ... }` group is left alone - it is a setting of that group,
    /// and the section parser refuses it by name rather than ignoring it.
    fn expand(&mut self, input: &str, depth: usize) -> Result<String, Error> {
        let mut expanded = String::with_capacity(input.len());
        let mut group_level = 0i32;
        for line in input.lines() {
            let cleaned = strip_comments(line).trim();
            if group_level == 0
                && let Some(directive) = IncludeDirective::parse(cleaned)
            {
                expanded.push_str(&self.splice(directive, depth)?);
                continue;
            }
            expanded.push_str(line);
            expanded.push('\n');
            group_level += brace_delta(cleaned);
        }
        Ok(expanded)
    }

    /// What one directive contributes to the expanded text.
    fn splice(&mut self, directive: IncludeDirective<'_>, depth: usize) -> Result<String, Error> {
        match directive {
            IncludeDirective::File(argument) => self.include_file(Path::new(argument), depth),
            IncludeDirective::Directory(argument) => self.include_dir(Path::new(argument), depth),
        }
    }

    /// One `include`: read the file and expand its own directives in turn.
    ///
    /// A path is used exactly as the configuration spells it, which is what MIT
    /// does (`fopen` on the token, relative to the process's working directory
    /// when it is relative) - no rebasing on the including file's directory.
    fn include_file(&mut self, path: &Path, depth: usize) -> Result<String, Error> {
        let depth = depth + 1;
        if depth > MAX_INCLUDE_DEPTH {
            return Err(Error::IncludeTooDeep {
                depth,
                limit: MAX_INCLUDE_DEPTH,
            });
        }
        // Resolving the path is how a file that does not exist is named rather
        // than skipped; it also gives the cycle check its canonical key.
        let canonical = std::fs::canonicalize(path).map_err(|source| Error::IncludeFile {
            path: path.to_path_buf(),
            source,
        })?;
        if self.open.contains(&canonical) {
            return Err(Error::IncludeCycle {
                path: path.to_path_buf(),
            });
        }
        let content = self.read_include(path)?;
        self.open.push(canonical);
        let expanded = self.expand(&content, depth);
        self.open.pop();
        expanded
    }

    /// One included file's text, counted against the file and byte caps.
    fn read_include(&mut self, path: &Path) -> Result<String, Error> {
        let count = self.files + 1;
        if count > MAX_INCLUDE_FILES {
            return Err(Error::IncludeTooMany {
                count,
                limit: MAX_INCLUDE_FILES,
            });
        }
        // Read at most one byte past what is left of the budget, so an oversize
        // file is refused without reading it into memory first.
        let remaining = MAX_INCLUDE_BYTES.saturating_sub(self.bytes);
        let file = std::fs::File::open(path).map_err(|source| Error::IncludeFile {
            path: path.to_path_buf(),
            source,
        })?;
        let mut bytes = Vec::new();
        file.take(remaining as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| Error::IncludeFile {
                path: path.to_path_buf(),
                source,
            })?;
        if bytes.len() > remaining {
            return Err(Error::IncludeTooLarge {
                bytes: self.bytes + bytes.len(),
                limit: MAX_INCLUDE_BYTES,
            });
        }
        let content = String::from_utf8(bytes).map_err(|error| Error::IncludeFile {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("not UTF-8 text: {error}"),
            ),
        })?;
        self.files = count;
        self.bytes += content.len();
        Ok(content)
    }

    /// One `includedir`: every accepted name, in alphanumeric order.
    ///
    /// The file cap is enforced while the directory is scanned, so a directory
    /// with more accepted names than the budget allows is refused before any
    /// name is sorted or any file is read.
    ///
    /// The directory's canonical path joins the open chain for as long as its
    /// files are being expanded, so a directory that is reached again through a
    /// symlink while it is being read - and an entry that is one of the
    /// directories already being read - is [`Error::IncludeCycle`] naming the
    /// path the configuration spelled, rather than a chain that only runs out of
    /// depth. The path is used exactly as the configuration spells it, as an
    /// `include` path is (`fopen` on the token, MIT's own rule).
    fn include_dir(&mut self, dir: &Path, depth: usize) -> Result<String, Error> {
        let canonical = std::fs::canonicalize(dir).map_err(|source| Error::IncludeDir {
            path: dir.to_path_buf(),
            source,
        })?;
        if self.open.contains(&canonical) {
            return Err(Error::IncludeCycle {
                path: dir.to_path_buf(),
            });
        }
        let entries = std::fs::read_dir(dir).map_err(|source| Error::IncludeDir {
            path: dir.to_path_buf(),
            source,
        })?;
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| Error::IncludeDir {
                path: dir.to_path_buf(),
                source,
            })?;
            // Matched as bytes, like MIT's `valid_name`, so a `.conf` name that is
            // not UTF-8 is included too; the path used to open a file is always
            // the one the directory entry carries.
            let name = entry.file_name();
            if includedir_name_is_valid(name.as_encoded_bytes()) {
                let count = self.files + names.len() + 1;
                if count > MAX_INCLUDE_FILES {
                    return Err(Error::IncludeTooMany {
                        count,
                        limit: MAX_INCLUDE_FILES,
                    });
                }
                names.push(name);
            }
        }
        // Byte order, which is `strcmp` order: MIT reads the directory's accepted
        // files in alphanumeric order.
        names.sort();
        self.open.push(canonical);
        let mut expanded = String::new();
        for name in names {
            expanded.push_str(&self.include_file(&dir.join(name), depth)?);
        }
        self.open.pop();
        Ok(expanded)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Config, Error, LibDefaults, MAX_INCLUDE_BYTES, MAX_INCLUDE_DEPTH, MAX_INCLUDE_FILES,
    };
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// The marker the parent sets when it re-executes this binary as a probe, so
    /// a normal run leaves the probe test inert.
    const PROBE_MARKER: &str = "RSKRB5_ENV_FREE_PROBE";
    /// Every probe line carries this prefix, so the parent can ignore the test
    /// harness's own output.
    const PROBE_PREFIX: &str = "rskrb5-probe:";
    /// This probe test's name in this binary, for the child's `--exact`.
    const PROBE_TEST: &str = "config::tests::env_free_fields_probe_child";
    /// The hostile `UID` the parent gives the child.
    const HOSTILE_UID: &str = "4242";
    /// The hostile `HOME` the parent gives the child.
    const HOSTILE_HOME: &str = "/attacker/home";

    /// The `UID`-derived default the environment-free constructors must produce:
    /// the path `LibDefaults::new` builds when `UID` is unset.
    const ENV_FREE_CLIENT_KEYTAB: &str = "/usr/local/var/krb5/user/0/client.keytab";

    /// The environment-free constructor's fields, and - as the control - the
    /// environment-reading constructor's, printed for the parent to assert on.
    #[test]
    fn env_free_fields_probe_child() {
        if std::env::var_os(PROBE_MARKER).is_none() {
            return;
        }
        let config = Config::new_without_env();
        let defaults = LibDefaults::new_without_env();
        let parsed = Config::parse_without_env("[libdefaults]\n").expect("empty config parses");
        let reading = LibDefaults::new();
        for (name, keytab, k5login) in [
            (
                "config",
                &config.libdefaults.default_client_keytab_name,
                &config.libdefaults.k5login_directory,
            ),
            (
                "defaults",
                &defaults.default_client_keytab_name,
                &defaults.k5login_directory,
            ),
            (
                "parsed",
                &parsed.libdefaults.default_client_keytab_name,
                &parsed.libdefaults.k5login_directory,
            ),
            (
                "reading",
                &reading.default_client_keytab_name,
                &reading.k5login_directory,
            ),
        ] {
            println!("{PROBE_PREFIX}{name}_client_keytab={keytab}");
            println!("{PROBE_PREFIX}{name}_k5login={k5login}");
        }
    }

    /// Run this binary as a child with a hostile `UID`/`HOME` - a child process,
    /// never this one's environment - and return the probe lines it
    /// printed.
    fn hostile_env_probe() -> Vec<String> {
        let executable = std::env::current_exe().expect("current_exe resolves");
        let output = Command::new(executable)
            .args(["--exact", PROBE_TEST, "--nocapture"])
            .env_clear()
            .env(PROBE_MARKER, "1")
            .env("UID", HOSTILE_UID)
            .env("HOME", HOSTILE_HOME)
            .output()
            .expect("probe child spawns");
        assert!(
            output.status.success(),
            "the probe child must exit 0: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.strip_prefix(PROBE_PREFIX))
            .map(str::to_owned)
            .collect()
    }

    /// The value of one probe line, if the child printed it.
    fn probe_field(lines: &[String], key: &str) -> String {
        lines
            .iter()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix('=').map(str::to_owned))
            .unwrap_or_else(|| panic!("the probe must print {key}: {lines:?}"))
    }

    /// The control, asserted by every test below: the child's environment really
    /// is hostile, so `LibDefaults::new` in that child follows it. Without this,
    /// an inert probe would make the env-free assertions pass for the wrong
    /// reason.
    fn assert_the_child_environment_is_hostile(lines: &[String]) {
        assert_eq!(
            probe_field(lines, "reading_client_keytab"),
            format!("/usr/local/var/krb5/user/{HOSTILE_UID}/client.keytab"),
            "the environment-reading constructor must follow the hostile UID"
        );
        assert_eq!(probe_field(lines, "reading_k5login"), HOSTILE_HOME);
    }

    /// `Config::new_without_env` reads neither `UID` nor `HOME`: hostile values
    /// in the process environment leave both derived fields at their
    /// deterministic non-env values.
    #[test]
    fn env_free_config_constructor_does_not_read_uid_or_home() {
        let lines = hostile_env_probe();
        assert_the_child_environment_is_hostile(&lines);
        assert_eq!(
            probe_field(&lines, "config_client_keytab"),
            ENV_FREE_CLIENT_KEYTAB,
            "the env-free config's keytab default is the UID-fallback path"
        );
        assert_eq!(probe_field(&lines, "config_k5login"), "");
    }

    /// The same for the `LibDefaults` constructor the two env-free config
    /// constructors share.
    #[test]
    fn env_free_libdefaults_constructor_does_not_read_uid_or_home() {
        let lines = hostile_env_probe();
        assert_the_child_environment_is_hostile(&lines);
        assert_eq!(
            probe_field(&lines, "defaults_client_keytab"),
            ENV_FREE_CLIENT_KEYTAB
        );
        assert_eq!(probe_field(&lines, "defaults_k5login"), "");
    }

    /// `Config::parse_without_env` must not reach `Config::parse` ->
    /// `Config::new` -> `LibDefaults::new`: it shares the parser, not the
    /// constructor.
    #[test]
    fn parse_without_env_does_not_read_uid_or_home() {
        let lines = hostile_env_probe();
        assert_the_child_environment_is_hostile(&lines);
        assert_eq!(
            probe_field(&lines, "parsed_client_keytab"),
            ENV_FREE_CLIENT_KEYTAB
        );
        assert_eq!(probe_field(&lines, "parsed_k5login"), "");
    }

    #[test]
    fn load_default_paths_loads_existing_platform_candidate() {
        let path = temp_file("load-default-paths");
        std::fs::write(
            &path,
            r#"
[libdefaults]
 default_realm = DEFAULT.GOKRB5
"#,
        )
        .expect("default config writes");

        let config =
            Config::load_default_paths([PathBuf::from("/missing/krb5.conf"), path.clone()])
                .expect("existing default path loads");
        let _ = std::fs::remove_file(&path);

        assert_eq!(config.libdefaults.default_realm, "DEFAULT.GOKRB5");
    }

    #[test]
    fn load_default_or_parse_paths_uses_embedded_when_no_default_exists() {
        let config = Config::load_default_or_parse_paths(
            r#"
[libdefaults]
 default_realm = EMBEDDED.GOKRB5
"#,
            [PathBuf::from("/missing/krb5.conf")],
        )
        .expect("embedded config parses");

        assert_eq!(config.libdefaults.default_realm, "EMBEDDED.GOKRB5");
    }

    #[test]
    fn load_default_or_parse_paths_does_not_fallback_when_default_is_invalid() {
        let path = temp_file("load-default-invalid");
        std::fs::write(
            &path,
            r#"
[libdefaults]
 dns_lookup_kdc = maybe
"#,
        )
        .expect("invalid default config writes");

        let error = Config::load_default_or_parse_paths(
            r#"
[libdefaults]
 default_realm = EMBEDDED.GOKRB5
"#,
            [path.clone()],
        )
        .expect_err("invalid existing default is returned");
        let _ = std::fs::remove_file(&path);

        assert!(matches!(error, Error::InvalidBoolean(value) if value == "maybe"));
    }

    fn temp_file(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "rskrb5-config-unit-{name}-{}-{nanos}",
            std::process::id()
        ))
    }

    /// A fresh directory for one fixture tree, unique per process and call.
    fn fixture_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "rskrb5-config-include-{name}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("fixture directory is created");
        dir
    }

    /// Write `contents` to `dir/name` and return the path it wrote.
    fn write_fixture(dir: &Path, name: &str, contents: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, contents).expect("fixture file writes");
        path
    }

    /// Remove a fixture tree. Cleanup never fails a test.
    fn remove_fixture(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    /// `include` splices the named file at the directive site, so a
    /// fragment's settings are in the configuration and a setting the parent
    /// writes *after* the directive still wins - the splice is positional, not a
    /// merge of two independently parsed files.
    #[test]
    fn include_file_splices_settings_at_directive_site() {
        let dir = fixture_dir("splice");
        let fragment = write_fixture(
            &dir,
            "fragment.conf",
            "[libdefaults]\n default_realm = FRAGMENT.EXAMPLE\n\
             [realms]\n FRAGMENT.EXAMPLE = {\n  kdc = kdc.fragment.example:88\n }\n",
        );
        let root = write_fixture(
            &dir,
            "krb5.conf",
            &format!(
                "include {}\n[libdefaults]\n default_realm = PARENT.EXAMPLE\n",
                fragment.display()
            ),
        );

        let config = Config::load(&root).expect("the split configuration loads");
        remove_fixture(&dir);

        assert!(
            config.realm("FRAGMENT.EXAMPLE").is_some(),
            "the fragment's realm is spliced into the configuration"
        );
        assert_eq!(
            config.libdefaults.default_realm, "PARENT.EXAMPLE",
            "a setting after the directive site still wins, so the splice is positional"
        );
    }

    /// `includedir` applies MIT's filename filter - a `.conf` name or a
    /// name made only of alphanumerics, dashes and underscores, never a dotfile -
    /// and reads the accepted names in alphanumeric order.
    ///
    /// The order assertion is the `default_realm` one: two accepted names set it,
    /// and the one that sorts last wins. The filter assertion is the empty realm
    /// list: only the two rejected names carry a `[realms]` section, so a realm
    /// appearing at all would mean one of them was read.
    #[test]
    fn includedir_filters_names_like_mit_and_sorts_alphanumerically() {
        let dir = fixture_dir("filter");
        let fragments = dir.join("fragments");
        std::fs::create_dir_all(&fragments).expect("fragment directory is created");
        write_fixture(
            &fragments,
            "10-first.conf",
            "[libdefaults]\n default_realm = FIRST.EXAMPLE\n",
        );
        write_fixture(
            &fragments,
            "20-flag",
            "[libdefaults]\n udp_preference_limit = 1\n",
        );
        write_fixture(
            &fragments,
            "30-last.conf",
            "[libdefaults]\n default_realm = LAST.EXAMPLE\n",
        );
        write_fixture(
            &fragments,
            "40-dotfile-suffix.bak",
            "[realms]\n REJECTED.EXAMPLE = {\n  kdc = kdc.rejected.example:88\n }\n",
        );
        write_fixture(
            &fragments,
            ".50-hidden.conf",
            "[realms]\n HIDDEN.EXAMPLE = {\n  kdc = kdc.hidden.example:88\n }\n",
        );
        let root = write_fixture(
            &dir,
            "krb5.conf",
            &format!("includedir {}\n", fragments.display()),
        );

        let config = Config::load(&root).expect("the split configuration loads");
        remove_fixture(&dir);

        assert_eq!(
            config.libdefaults.default_realm, "LAST.EXAMPLE",
            "the accepted names are read in alphanumeric order, so the last one wins"
        );
        assert_eq!(config.libdefaults.udp_preference_limit, 1);
        assert!(
            config.realms.is_empty(),
            "a `.bak` name and a dotfile are not included: {:?}",
            config.realms
        );
    }

    /// An include chain that returns to a file it is already reading is a
    /// named cycle error, not unbounded recursion.
    ///
    /// `a.conf` is the file the caller loaded, so it is on the open chain from
    /// the start: the chain returns to it, and that is the file the error
    /// names. Before the root was tracked the parser read `a.conf` a second time
    /// and detected the cycle one level further down, at `b.conf`.
    #[test]
    fn include_cycle_is_a_named_error() {
        let dir = fixture_dir("cycle");
        let second = write_fixture(&dir, "b.conf", "");
        let first = write_fixture(&dir, "a.conf", &format!("include {}\n", second.display()));
        std::fs::write(&second, format!("include {}\n", first.display()))
            .expect("the second fixture writes");

        let error = Config::load(&first).expect_err("a cycle is refused");
        remove_fixture(&dir);

        assert!(
            matches!(&error, Error::IncludeCycle { path } if path == &first),
            "the cycle names the file it returned to, which is already being read: {error:?}"
        );
    }

    /// Nesting past [`MAX_INCLUDE_DEPTH`] is a named error carrying the
    /// depth it reached and the limit.
    #[test]
    fn include_depth_limit_is_named() {
        let dir = fixture_dir("depth");
        let mut paths = Vec::new();
        for level in 1..=10 {
            paths.push(write_fixture(&dir, &format!("level{level}.conf"), ""));
        }
        for (index, path) in paths.iter().enumerate() {
            let next = paths.get(index + 1);
            let contents =
                next.map_or_else(String::new, |next| format!("include {}\n", next.display()));
            std::fs::write(path, contents).expect("the fixture writes");
        }

        let error = Config::load(&paths[0]).expect_err("a chain past the limit is refused");
        remove_fixture(&dir);

        assert!(
            matches!(
                error,
                Error::IncludeTooDeep {
                    depth: 9,
                    limit: MAX_INCLUDE_DEPTH
                }
            ),
            "eight levels of include are read; the ninth is past the limit of {MAX_INCLUDE_DEPTH}: {error:?}"
        );
    }

    /// More included files than [`MAX_INCLUDE_FILES`] is a named error.
    #[test]
    fn include_file_count_limit_is_named() {
        let dir = fixture_dir("count");
        let fragments = dir.join("fragments");
        std::fs::create_dir_all(&fragments).expect("fragment directory is created");
        for index in 0..=MAX_INCLUDE_FILES {
            write_fixture(
                &fragments,
                &format!("f{index:02}.conf"),
                "[libdefaults]\n default_realm = COUNT.EXAMPLE\n",
            );
        }
        let root = write_fixture(
            &dir,
            "krb5.conf",
            &format!("includedir {}\n", fragments.display()),
        );

        let error = Config::load(&root).expect_err("too many included files are refused");
        remove_fixture(&dir);

        assert!(
            matches!(
                error,
                Error::IncludeTooMany {
                    count: 65,
                    limit: MAX_INCLUDE_FILES
                }
            ),
            "the 65th file is past the limit of {MAX_INCLUDE_FILES}: {error:?}"
        );
    }

    /// An `includedir` with more accepted names than the file cap is refused while
    /// the directory is scanned: its first entry cannot be read, and the cap is
    /// still what is reported, so no file was opened.
    #[test]
    fn includedir_past_the_file_cap_is_refused_before_any_file_is_read() {
        let dir = fixture_dir("count-early");
        let fragments = dir.join("fragments");
        std::fs::create_dir_all(fragments.join("f00.conf"))
            .expect("an unreadable first entry is created");
        for index in 1..=MAX_INCLUDE_FILES {
            write_fixture(&fragments, &format!("f{index:02}.conf"), "[libdefaults]\n");
        }
        let root = write_fixture(
            &dir,
            "krb5.conf",
            &format!("includedir {}\n", fragments.display()),
        );

        let error = Config::load(&root).expect_err("too many accepted names are refused");
        remove_fixture(&dir);

        assert!(
            matches!(
                error,
                Error::IncludeTooMany {
                    limit: MAX_INCLUDE_FILES,
                    ..
                }
            ),
            "the cap is reported before the unreadable first entry is opened: {error:?}"
        );
    }

    /// `includedir` matches names as bytes, like MIT's `valid_name`: a `.conf`
    /// name that is not UTF-8 is included. Linux only, because some filesystems
    /// refuse such names.
    #[cfg(target_os = "linux")]
    #[test]
    fn includedir_matches_names_as_bytes_like_mit() {
        use std::os::unix::ffi::OsStrExt;
        let dir = fixture_dir("byte-names");
        let fragments = dir.join("fragments");
        std::fs::create_dir_all(&fragments).expect("fragment directory is created");
        let name = std::ffi::OsStr::from_bytes(b"\xff-realm.conf");
        std::fs::write(
            fragments.join(name),
            "[libdefaults]\n default_realm = BYTES.EXAMPLE\n",
        )
        .expect("a .conf name that is not UTF-8 is created");
        let root = write_fixture(
            &dir,
            "krb5.conf",
            &format!("includedir {}\n", fragments.display()),
        );

        let config = Config::load(&root).expect("the directory loads");
        remove_fixture(&dir);

        assert_eq!(config.libdefaults.default_realm, "BYTES.EXAMPLE");
    }

    /// Included bytes past [`MAX_INCLUDE_BYTES`] are a named error - and the
    /// oversize file is refused rather than read into memory whole.
    #[test]
    fn include_total_byte_limit_is_named() {
        let dir = fixture_dir("bytes");
        let oversize = write_fixture(
            &dir,
            "big.conf",
            &format!(
                "#{}\n[libdefaults]\n default_realm = BIG.EXAMPLE\n",
                "x".repeat(MAX_INCLUDE_BYTES)
            ),
        );
        let root = write_fixture(
            &dir,
            "krb5.conf",
            &format!("include {}\n", oversize.display()),
        );

        let error = Config::load(&root).expect_err("an oversize include is refused");
        remove_fixture(&dir);

        assert!(
            matches!(
                error,
                Error::IncludeTooLarge {
                    bytes: 1_048_577,
                    limit: MAX_INCLUDE_BYTES
                }
            ),
            "the read stops one byte past the limit of {MAX_INCLUDE_BYTES}: {error:?}"
        );
    }

    /// An `include` naming a file that cannot be read is a named error
    /// carrying the path - MIT's `PROF_FAIL_INCLUDE_FILE`, never a silent skip.
    #[test]
    fn unreadable_include_file_is_named() {
        let dir = fixture_dir("unreadable-file");
        let missing = dir.join("missing.conf");
        let root = write_fixture(
            &dir,
            "krb5.conf",
            &format!("include {}\n", missing.display()),
        );

        let error = Config::load(&root).expect_err("a missing include is refused");
        remove_fixture(&dir);

        assert!(
            matches!(&error, Error::IncludeFile { path, source } if path == &missing && source.kind() == std::io::ErrorKind::NotFound),
            "the error names the file the directive named: {error:?}"
        );
    }

    /// An `includedir` naming a directory that cannot be listed is a named
    /// error - MIT's `PROF_FAIL_INCLUDE_DIR`.
    #[test]
    fn unreadable_includedir_is_named() {
        let dir = fixture_dir("unreadable-dir");
        let missing = dir.join("missing-dir");
        let root = write_fixture(
            &dir,
            "krb5.conf",
            &format!("includedir {}\n", missing.display()),
        );

        let error = Config::load(&root).expect_err("a missing includedir is refused");
        remove_fixture(&dir);

        assert!(
            matches!(&error, Error::IncludeDir { path, source } if path == &missing && source.kind() == std::io::ErrorKind::NotFound),
            "the error names the directory the directive named: {error:?}"
        );
    }

    /// A `KRB5_CONFIG` path list keeps MIT's order with an include in it -
    /// files are read in list order, each file's includes are expanded where the
    /// directive sits, and a later file's settings still win.
    #[test]
    fn krb5_config_path_list_preserves_mit_order_with_includes() {
        let dir = fixture_dir("path-list");
        let fragment = write_fixture(
            &dir,
            "fragment.conf",
            "[libdefaults]\n default_realm = INCLUDE.EXAMPLE\n\
             [realms]\n INCLUDE.EXAMPLE = {\n  kdc = kdc.include.example:88\n }\n",
        );
        let first = write_fixture(
            &dir,
            "first.conf",
            &format!(
                "include {}\n[libdefaults]\n udp_preference_limit = 1\n",
                fragment.display()
            ),
        );
        let second = write_fixture(
            &dir,
            "second.conf",
            "[libdefaults]\n default_realm = SECOND.EXAMPLE\n udp_preference_limit = 2\n",
        );

        let config = Config::load_paths([first, second]).expect("the path list loads");
        remove_fixture(&dir);

        assert_eq!(
            config.libdefaults.default_realm, "SECOND.EXAMPLE",
            "the later file in the list wins over the included fragment"
        );
        assert_eq!(
            config.libdefaults.udp_preference_limit, 2,
            "and over the file that carried the include"
        );
        assert!(
            config.realm("INCLUDE.EXAMPLE").is_some(),
            "the include inside the first file was expanded at its directive site"
        );
    }

    /// A root file that includes itself is a cycle, and the root is what
    /// the cycle returns to - so the root is on the open stack before its own
    /// directives expand.
    ///
    /// The chain is seven files long on purpose: the root is reached again while
    /// the parser is already eight levels down, which is the deepest include the
    /// limit allows. Without the root on the open stack the recursion runs one
    /// level past [`MAX_INCLUDE_DEPTH`] and is named as merely deep.
    #[test]
    fn a_root_file_including_itself_is_a_cycle() {
        let dir = fixture_dir("root-self");
        let root = write_fixture(&dir, "krb5.conf", "");
        let mut chain = Vec::new();
        for level in 1..=7 {
            chain.push(write_fixture(&dir, &format!("level{level}.conf"), ""));
        }
        for (index, path) in chain.iter().enumerate() {
            let next = chain
                .get(index + 1)
                .cloned()
                .unwrap_or_else(|| root.clone());
            std::fs::write(path, format!("include {}\n", next.display()))
                .expect("the chain writes");
        }
        std::fs::write(&root, format!("include {}\n", chain[0].display()))
            .expect("the root writes");

        let error = Config::load(&root).expect_err("a root that includes itself is refused");
        remove_fixture(&dir);

        assert!(
            matches!(&error, Error::IncludeCycle { path } if path == &root),
            "the root file is already being read, so returning to it is a cycle: {error:?}"
        );
    }

    /// A path-list root that a child includes is the same cycle. Every
    /// top-level file is on the open stack before the text it contributed is
    /// expanded, so a child's `include` of the root is named rather than the
    /// root being read a second time.
    #[test]
    fn a_path_list_root_included_by_a_child_is_a_cycle() {
        let dir = fixture_dir("path-list-root");
        let first = write_fixture(
            &dir,
            "first.conf",
            "[libdefaults]\n default_realm = FIRST.EXAMPLE\n",
        );
        let second = write_fixture(
            &dir,
            "second.conf",
            &format!("include {}\n", first.display()),
        );

        let error = Config::load_paths([&first, &second])
            .expect_err("a path-list root a child includes is refused");
        remove_fixture(&dir);

        assert!(
            matches!(&error, Error::IncludeCycle { path } if path == &first),
            "the root of the path list is already being read: {error:?}"
        );
    }

    /// An `includedir` reached again through a symlink while its files
    /// are being expanded is a cycle, named at the path the directive spelled -
    /// the canonical directories being expanded are tracked, so the chain is
    /// named rather than merely deep.
    ///
    /// `top/up` is `top` itself, and the directive that names it sits at the
    /// eighth include level, one past where an untracked directory would leave
    /// the file-level check.
    #[cfg(target_family = "unix")]
    #[test]
    fn a_symlinked_includedir_cycle_is_named() {
        let dir = fixture_dir("symlinked-dir");
        let top = dir.join("top");
        std::fs::create_dir_all(&top).expect("the included directory is created");
        std::os::unix::fs::symlink(&top, top.join("up")).expect("the symlink is created");
        write_fixture(
            &top,
            "00.conf",
            "[libdefaults]\n udp_preference_limit = 1\n",
        );
        let mut chain = Vec::new();
        for level in 1..=7 {
            chain.push(top.join(format!("tmp{level}.conf")));
        }
        std::fs::write(
            &chain[6],
            format!("includedir {}\n", top.join("up").display()),
        )
        .expect("the chain writes");
        for index in (0..6).rev() {
            std::fs::write(
                &chain[index],
                format!("include {}\n", chain[index + 1].display()),
            )
            .expect("the chain writes");
        }
        write_fixture(
            &top,
            "10.conf",
            &format!("include {}\n", chain[0].display()),
        );
        let cycle = top.join("up");
        let root = write_fixture(
            &dir,
            "krb5.conf",
            &format!("includedir {}\n", top.display()),
        );

        let error = Config::load(&root).expect_err("the symlinked cycle is refused");
        remove_fixture(&dir);

        assert!(
            matches!(&error, Error::IncludeCycle { path } if path == &cycle),
            "the symlink names the directory that is already being read: {error:?}"
        );
    }
}
