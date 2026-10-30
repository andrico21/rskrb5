//! Ticket transit-policy enforcement.

use super::{Error, Principal, Validator, kerberos_string_to_string};

impl Validator<'_> {
    /// Enforce RFC 4120 section 2.7 before replay admission.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TransitPolicyRejected`] for unchecked cross-realm paths
    /// without explicit approval, or [`Error::InvalidString`] for invalid realms.
    pub(super) fn validate_transit(
        &self,
        service: &Principal,
        ticket: &rasn_kerberos::EncTicketPart,
    ) -> Result<(), Error> {
        let client_realm = kerberos_string_to_string(&ticket.crealm)?;
        if client_realm != service.realm
            && !ticket.flags.0.get(12).is_some_and(|bit| *bit)
            && !self.transit_policy.as_ref().is_some_and(|policy| {
                policy.accepts(&client_realm, &service.realm, &ticket.transited)
            })
        {
            return Err(Error::TransitPolicyRejected);
        }
        Ok(())
    }
}
