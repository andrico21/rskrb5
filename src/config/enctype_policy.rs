impl LibDefaults {
    /// Reject an explicit request list that names an enctype the explicit
    /// `permitted_enctypes` allowlist does not permit.
    ///
    /// Dropping the enctype instead would silently send a narrower request
    /// list than the operator configured. Seeded (implicit) request lists are
    /// not checked here; `AsReq::from_libdefaults` and
    /// `TgsReq::from_libdefaults` narrow them to the allowlist.
    ///
    /// Unsupported and policy-disabled names are skipped after all sections
    /// are read. Every explicit list must retain at least one usable entry;
    /// treating an empty allowlist as "no policy" would permit every enctype.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoUsableEnctypes`] for an unusable request list,
    /// [`Error::NoPermittedEnctypes`] when the explicit allowlist
    /// resolves to no usable enctype, and [`Error::EnctypeNotPermitted`]
    /// naming the first explicit request list and enctype outside the
    /// allowlist.
    fn validate_explicit_enctypes(&mut self, enctypes: EnctypeParseState) -> Result<(), Error> {
        if enctypes.tkt_explicit {
            self.default_tkt_enctypes =
                self.usable_explicit_enctypes(&self.default_tkt_enctypes, "default_tkt_enctypes")?;
        }
        if enctypes.tgs_explicit {
            self.default_tgs_enctypes =
                self.usable_explicit_enctypes(&self.default_tgs_enctypes, "default_tgs_enctypes")?;
        }
        if self.permitted_enctypes_explicit.is_enabled() {
            self.permitted_enctypes =
                self.usable_explicit_enctypes(&self.permitted_enctypes, "permitted_enctypes")?;
        }
        if !self.permitted_enctypes_explicit.is_enabled() {
            return Ok(());
        }
        let permitted = self.permitted_enctype_ids();
        if permitted.is_empty() {
            return Err(Error::NoPermittedEnctypes {
                names: self.permitted_enctypes.clone(),
            });
        }
        let request_lists = [
            (
                enctypes.tkt_explicit,
                "default_tkt_enctypes",
                &self.default_tkt_enctypes,
            ),
            (
                enctypes.tgs_explicit,
                "default_tgs_enctypes",
                &self.default_tgs_enctypes,
            ),
        ];
        for (explicit, key, names) in request_lists {
            if !explicit {
                continue;
            }
            // Names without a supported ID are never requested, so only
            // supported IDs can be narrowed away.
            let not_permitted = names
                .iter()
                .find(|name| supported_enctype_id(name).is_some_and(|id| !permitted.contains(&id)));
            if let Some(name) = not_permitted {
                return Err(Error::EnctypeNotPermitted {
                    key,
                    enctype: name.clone(),
                });
            }
        }
        Ok(())
    }

    /// Skip unsupported or disabled names under the final section's policy.
    ///
    /// # Errors
    /// Returns a named error with the original input when no usable name remains.
    fn usable_explicit_enctypes(
        &self,
        names: &[String],
        key: &'static str,
    ) -> Result<Vec<String>, Error> {
        let usable: Vec<String> = names
            .iter()
            .filter(|name| supported_enctype_id(name).is_some() && self.enctype_enabled(name))
            .cloned()
            .collect();
        if usable.is_empty() {
            return Err(if key == "permitted_enctypes" {
                Error::NoPermittedEnctypes {
                    names: names.to_vec(),
                }
            } else {
                Error::NoUsableEnctypes {
                    key,
                    names: names.to_vec(),
                }
            });
        }
        Ok(usable)
    }
    /// Whether both family policy and weak-crypto policy permit this name.
    fn enctype_enabled(&self, name: &str) -> bool {
        let family_enabled = match supported_enctype_id(name) {
            Some(23_i32 | 24_i32) => self.allow_rc4.is_enabled(),
            Some(16_i32) => self.allow_des3.is_enabled(),
            Some(_) | None => true,
        };
        family_enabled && (self.allow_weak_crypto.is_enabled() || !is_weak_enctype(name))
    }

    /// Derives implemented IDs with the current independent policy switches.
    fn effective_enctype_ids(&self, names: &[String]) -> Vec<i32> {
        names
            .iter()
            .filter(|name| self.enctype_enabled(name))
            .filter_map(|name| supported_enctype_id(name))
            .collect()
    }
}
