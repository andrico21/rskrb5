use super::{Error, KRB_NT_PRINCIPAL, KRB_NT_SRV_INST};

/// Kerberos principal identity used by client exchanges.
///
/// Derived equality and hashing compare all fields, including `name_type`.
/// Protocol identity matching compares realm and ordered components only.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct Principal {
    /// Principal realm.
    pub realm: String,
    /// Kerberos name type. Name type is advisory and is not used for matching.
    pub name_type: i32,
    /// Principal name components.
    pub components: Vec<String>,
}

impl Principal {
    /// Create a principal.
    #[inline]
    pub fn new<I, S, P>(realm: P, name_type: i32, components: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
        P: Into<String>,
    {
        Self {
            realm: realm.into(),
            name_type,
            components: components.into_iter().map(Into::into).collect(),
        }
    }

    /// Create a normal client principal.
    #[inline]
    pub fn user<P, Q>(realm: P, name: Q) -> Self
    where
        P: Into<String>,
        Q: Into<String>,
    {
        Self::new(realm, KRB_NT_PRINCIPAL, [name.into()])
    }

    /// Parse a single-component user principal in `user@REALM` form.
    ///
    /// Separator characters may be escaped with `\`, for example
    /// `user\@name@REALM` parses as user component `user@name`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPrincipalName`] when the value is empty, lacks
    /// exactly one unescaped `@` realm separator, has an empty name, realm or
    /// name component, ends with a dangling escape character, or contains more
    /// than one name component.
    #[inline]
    pub fn parse_user<P>(value: P) -> Result<Self, Error>
    where
        P: AsRef<str>,
    {
        let text = value.as_ref();
        let (name, realm) = parse_name_and_realm(text)?;
        let components = parse_principal_components(text, name)?;
        let Ok([component]) = <[String; 1]>::try_from(components) else {
            return Err(invalid_principal_name(
                text,
                "user principal must contain exactly one name component",
            ));
        };
        Ok(Self::user(realm, component))
    }

    /// Parse a host service principal in `service/host@REALM` form.
    ///
    /// This creates a name type 2 service principal with components
    /// `[service, host]`, matching the host-based service shape used by
    /// native GSSAPI.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPrincipalName`] when the value is empty, lacks
    /// exactly one unescaped `@` realm separator, has an empty name, realm or
    /// name component, ends with a dangling escape character, or does not
    /// contain exactly the service and host components.
    #[inline]
    pub fn parse_service<P>(value: P) -> Result<Self, Error>
    where
        P: AsRef<str>,
    {
        let text = value.as_ref();
        let (name, realm) = parse_name_and_realm(text)?;
        let components = parse_principal_components(text, name)?;
        if components.len() != 2 {
            return Err(invalid_principal_name(
                text,
                "service principal must contain service and host components",
            ));
        }
        Ok(Self::new(realm, KRB_NT_SRV_INST, components))
    }

    /// Create a host-based service principal with an empty realm.
    ///
    /// High-level clients resolve the empty service realm from
    /// `[domain_realm]` and then from the client realm.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPrincipalName`] when the service or host name is
    /// empty.
    #[inline]
    pub fn host_based_service<P, Q>(service: P, host: Q) -> Result<Self, Error>
    where
        P: AsRef<str>,
        Q: AsRef<str>,
    {
        host_based_service_principal(service.as_ref(), host.as_ref(), "")
    }

    /// Create a host-based service principal in a specific realm.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPrincipalName`] when the service name, host name
    /// or realm is empty.
    #[inline]
    pub fn host_based_service_in_realm<P, Q, R>(
        service: P,
        host: Q,
        realm: R,
    ) -> Result<Self, Error>
    where
        P: AsRef<str>,
        Q: AsRef<str>,
        R: AsRef<str>,
    {
        let realm_name = realm.as_ref();
        if realm_name.is_empty() {
            return Err(invalid_principal_name(
                realm_name,
                "host-based service realm is empty",
            ));
        }
        host_based_service_principal(service.as_ref(), host.as_ref(), realm_name)
    }

    /// Create the TGT service principal for a realm.
    #[inline]
    pub fn tgt_service<P>(realm: P) -> Self
    where
        P: Into<String>,
    {
        let realm_name = realm.into();
        Self::new(
            realm_name.clone(),
            KRB_NT_SRV_INST,
            ["krbtgt".to_owned(), realm_name],
        )
    }

    #[must_use]
    /// Principal components joined by `/`.
    #[inline]
    pub fn name(&self) -> String {
        self.components.join("/")
    }
}

/// Build a name type 2 host-based service principal with a lowercase host.
///
/// # Errors
///
/// Returns [`Error::InvalidPrincipalName`] when the service or host name is
/// empty.
fn host_based_service_principal(
    service: &str,
    host: &str,
    realm: &str,
) -> Result<Principal, Error> {
    if service.is_empty() {
        return Err(invalid_principal_name(
            service,
            "host-based service name is empty",
        ));
    }
    if host.is_empty() {
        return Err(invalid_principal_name(
            host,
            "host-based service host is empty",
        ));
    }
    // RFC 4120 section 6.2.1: where the host name is not case sensitive (DNS),
    // it must be lowercase. Fold only the host here so both host-based
    // constructors agree on one identity per DNS peer; the service component,
    // the realm and the explicit `parse_service` path stay case-sensitive.
    Ok(Principal::new(
        realm,
        KRB_NT_SRV_INST,
        [service.to_owned(), host.to_ascii_lowercase()],
    ))
}

/// Split `value` at its single unescaped `@` into the still-escaped name and
/// the unescaped realm.
///
/// # Errors
///
/// Returns [`Error::InvalidPrincipalName`] when the value is empty, has no or
/// more than one unescaped `@`, has an empty name or realm, or the realm ends
/// with a dangling escape character.
fn parse_name_and_realm(value: &str) -> Result<(&str, String), Error> {
    if value.is_empty() {
        return Err(invalid_principal_name(value, "principal name is empty"));
    }
    let parts = split_unescaped(value, '@');
    let &[name, escaped_realm] = parts.as_slice() else {
        return Err(invalid_principal_name(
            value,
            if parts.len() < 2 {
                "principal realm separator is missing"
            } else {
                "principal contains more than one unescaped realm separator"
            },
        ));
    };
    if name.is_empty() {
        return Err(invalid_principal_name(
            value,
            "principal name component is empty",
        ));
    }
    let realm = unescape_principal_component(value, escaped_realm)?;
    if realm.is_empty() {
        return Err(invalid_principal_name(value, "principal realm is empty"));
    }
    Ok((name, realm))
}

/// Split the escaped principal `name` at unescaped `/` and unescape each
/// component; `value` is the full input, quoted in errors.
///
/// # Errors
///
/// Returns [`Error::InvalidPrincipalName`] when a component ends with a
/// dangling escape character or is empty.
fn parse_principal_components(value: &str, name: &str) -> Result<Vec<String>, Error> {
    let components = split_unescaped(name, '/')
        .into_iter()
        .map(|component| unescape_principal_component(value, component))
        .collect::<Result<Vec<_>, _>>()?;
    if components.iter().any(String::is_empty) {
        return Err(invalid_principal_name(
            value,
            "principal contains an empty name component",
        ));
    }
    Ok(components)
}

/// Split `value` at every `separator` not preceded by an escaping `\`,
/// keeping the escapes in the returned parts.
fn split_unescaped(value: &str, separator: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut rest = value;
    loop {
        let mut escaped = false;
        let position = rest.char_indices().find_map(|(index, ch)| {
            if escaped {
                escaped = false;
                None
            } else if ch == '\\' {
                escaped = true;
                None
            } else if ch == separator {
                Some(index)
            } else {
                None
            }
        });
        let Some((part, tail)) = position.and_then(|index| rest.split_at_checked(index)) else {
            parts.push(rest);
            return parts;
        };
        parts.push(part);
        // `tail` starts with the separator found above.
        rest = tail.strip_prefix(separator).unwrap_or_default();
    }
}

/// Remove the `\` escapes from one principal component; `value` is the full
/// input, quoted in errors.
///
/// # Errors
///
/// Returns [`Error::InvalidPrincipalName`] when the component ends with a
/// dangling escape character.
fn unescape_principal_component(value: &str, component: &str) -> Result<String, Error> {
    let mut escaped = false;
    let mut out = String::with_capacity(component.len());
    for ch in component.chars() {
        if escaped {
            out.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else {
            out.push(ch);
        }
    }
    if escaped {
        return Err(invalid_principal_name(
            value,
            "principal contains a trailing escape character",
        ));
    }
    Ok(out)
}

/// Build the [`Error::InvalidPrincipalName`] error for `value`.
fn invalid_principal_name(value: &str, reason: &'static str) -> Error {
    Error::InvalidPrincipalName {
        value: value.to_owned(),
        reason,
    }
}
