# SPNEGO and GSS review disposition

Each row's commit is the commit with the ID in its subject; this avoids self-referential hashes.
Full red runs and acceptance output: `task-29-rskrb5-ng-own-way.log` in the execution evidence.

| ID | Status | Tests and commit | Behaviour change for CHANGELOG | Dismissal evidence |
| --- | --- | --- | --- | --- |
| RSK-84FA90AE | fixed | `unsealed_wrap_applies_rrc_on_decode_and_encode`; commit `(RSK-84FA90AE)` | Unsealed Wrap tokens apply RRC modulo body length on encoding and decoding. | N/A |
