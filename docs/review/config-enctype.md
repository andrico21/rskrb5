# Configuration and enctype review dispositions

Commands, initial red runs and fix-reversal QA are recorded in
`task-36-rskrb5-ng-own-way.log`. Acceptance is pending until all rows are done.

| ID | Status | Tests / commit | Behaviour change for CHANGELOG | Dismissal evidence |
|---|---|---|---|---|
| RSK-40161D92 / lead `apply_section/realms-replacement-dns-fallback` | fixed | `repeated_realms_preserve_configured_endpoints`, `repeated_realms_compose_across_files`; commit suffix `(RSK-40161D92)` | Repeated realm sections, path-list files and includes compose by case-sensitive realm identity. List relations append in file order with final markers preserved; later scalar values override. Kpasswd administration fallback runs after composition. Configured routes no longer disappear into DNS fallback. | — |
| RSK-77250646 / upstream #4 | fixed | `assigned_enctype_names_control_encoded_request`, `permitted_enctypes_survive_a_serde_round_trip`; commit suffix `(RSK-77250646)` | Enctype names are the sole stored policy. Derived-ID methods replace writable fields/builders; request options, reply checks, diagnostics and compatibility JSON derive from current names. Empty request lists fail closed instead of substituting defaults. | — |
