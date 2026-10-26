# Client review dispositions

Each commit named below contains its fix and regression. Full commands, red
runs, acceptance output and failure QA are in the task-33 evidence log.

| ID | Status | Tests / commit | Behaviour change for CHANGELOG | Dismissal evidence |
|---|---|---|---|---|
| RSK-AFE184E0 | fixed | `tgs_authenticator_uses_client_realm_when_issuer_differs`; `client: Use client realm in TGS authenticators (RSK-AFE184E0)` | Cross-realm TGS authenticators identify the client realm rather than ticket issuer (RFC 4120 §5.5.1). | — |
