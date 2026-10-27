# Configuration and enctype review dispositions

Commands, initial red runs and fix-reversal QA are recorded in
`task-36-rskrb5-ng-own-way.log`. Acceptance is pending until all rows are done.

| ID | Status | Tests / commit | Behaviour change for CHANGELOG | Dismissal evidence |
|---|---|---|---|---|
| RSK-40161D92 / lead `apply_section/realms-replacement-dns-fallback` | fixed | `repeated_realms_preserve_configured_endpoints`, `repeated_realms_compose_across_files`; commit suffix `(RSK-40161D92)` | Repeated realm sections, path-list files and includes compose by case-sensitive realm identity. List relations append in file order with final markers preserved; later scalar values override. Kpasswd administration fallback runs after composition. Configured routes no longer disappear into DNS fallback. | — |
