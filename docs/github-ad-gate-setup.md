# GitHub Active Directory Gate Setup

This runbook prepares a strict `TESTAD=1 TESTAD_REQUIRED=1` GitHub Actions
gate. The gate is live infrastructure evidence, not a Docker fixture. Keep it
blocked until the repository has the required secrets and reachable AD
endpoints.

## Status In rskrb5-ng

The rskrb5-ng CI workflow (`.github/workflows/ci.yml`) has **no AD job**, and
its `workflow_dispatch` trigger declares no inputs. The upstream
`clelange/rskrb5` workflow had an `active-directory-integration` job dispatched
with AD inputs; its runs are recorded in `docs/gokrb5-parity.toml` as
historical upstream evidence, not as rskrb5-ng gates.

This runbook therefore covers two things: the secret setup and readiness
check, which work today, and the requirements an AD job must meet once it is
restored to `ci.yml` together with its dispatch inputs.
`scripts/check-github-ad-gate.py --dispatch` refuses to dispatch until then.

## Runner Mode

The upstream AD job ran on GitHub-hosted `ubuntu-latest`. A restored job on
GitHub-hosted runners can prove the strict AD gate only when the AD endpoints
are reachable from GitHub's network or through a tunnel started by the workflow.
If the AD lab is private, either expose a controlled route or run the job on a
self-hosted Linux x64 runner near the lab.

The self-hosted runner mode expects these labels:

- `self-hosted`
- `linux`
- `x64`
- `rskrb5-ad`

Use this registration sequence only if the AD job uses the self-hosted runner
labels:

```sh
REPO=andrico21/rskrb5-ng
TOKEN=$(gh api --method POST "repos/$REPO/actions/runners/registration-token" --jq .token)

# Run inside the extracted GitHub Actions runner directory.
./config.sh --url "https://github.com/$REPO" --token "$TOKEN" --labels rskrb5-ad
./svc.sh install
./svc.sh start
```

Do not store the registration token. It is short-lived and should only be used
on the runner host.

## Network Requirements

The runner must satisfy these operational requirements:

- Linux x64 environment with outbound GitHub access for Actions checkout and
  toolchain setup.
- Network route from the runner to both AD KDC endpoints on TCP and UDP `88`.
- Network route to both kpasswd/admin endpoints on TCP `464` when
  `TEST_AD_CHECK_ADMIN_REACHABILITY=1` is used.
- Clock synchronized with both domain controllers inside normal Kerberos skew
  tolerance.
- Access to the AD lab described in [`ad-lab-provisioning.md`](ad-lab-provisioning.md).

An AD job installs the Rust toolchain itself. No keytabs live on disk on the
runner before the job starts; the job reads keytab bytes from Actions secrets.

## Required Secrets

Set these repository Actions secrets. Repository or org repo-selected secrets
work. Do not rely on Environment secrets unless the AD job sets an
`environment:`.

Endpoint secrets are plain `host:port` strings:

| Secret | Example |
|---|---|
| `TEST_AD_USER_KDC_ADDR` | `192.168.88.100:88` |
| `TEST_AD_RESOURCE_KDC_ADDR` | `192.168.88.101:88` |
| `TEST_AD_USER_ADMIN_ADDR` | `192.168.88.100:464` |
| `TEST_AD_RESOURCE_ADMIN_ADDR` | `192.168.88.101:464` |

Set endpoint secrets only when they identify real AD endpoints reachable from
the selected runner. Do not use random, placeholder, or reserved addresses to
make the strict readiness check pass; that only moves the failure to the live
reachability preflight. While no AD lab is available, use the keytab-secret
dry-run instead.

Keytab secrets are standard base64 of the complete MIT keytab bytes:

| Secret | Keytab content |
|---|---|
| `TEST_AD_TESTUSER1_KEYTAB_BASE64` | `testuser1@USER.GOKRB5` |
| `TEST_AD_TESTUSER2_KEYTAB_BASE64` | `testuser2@USER.GOKRB5` |
| `TEST_AD_TESTUSER3_KEYTAB_BASE64` | `testuser3@USER.GOKRB5` |
| `TEST_AD_SYSHTTP_KEYTAB_BASE64` | `sysHTTP@RES.GOKRB5` |

Example secret setup:

```sh
REPO=andrico21/rskrb5-ng

printf '%s' '192.168.88.100:88'  | gh secret set TEST_AD_USER_KDC_ADDR --repo "$REPO" --app actions
printf '%s' '192.168.88.101:88'  | gh secret set TEST_AD_RESOURCE_KDC_ADDR --repo "$REPO" --app actions
printf '%s' '192.168.88.100:464' | gh secret set TEST_AD_USER_ADMIN_ADDR --repo "$REPO" --app actions
printf '%s' '192.168.88.101:464' | gh secret set TEST_AD_RESOURCE_ADMIN_ADDR --repo "$REPO" --app actions

base64 < /secure/ad/testuser1.keytab | tr -d '\n' | gh secret set TEST_AD_TESTUSER1_KEYTAB_BASE64 --repo "$REPO" --app actions
base64 < /secure/ad/testuser2.keytab | tr -d '\n' | gh secret set TEST_AD_TESTUSER2_KEYTAB_BASE64 --repo "$REPO" --app actions
base64 < /secure/ad/testuser3.keytab | tr -d '\n' | gh secret set TEST_AD_TESTUSER3_KEYTAB_BASE64 --repo "$REPO" --app actions
base64 < /secure/ad/sysHTTP.keytab   | tr -d '\n' | gh secret set TEST_AD_SYSHTTP_KEYTAB_BASE64 --repo "$REPO" --app actions
```

## Readiness And Dispatch

Check GitHub-side secret readiness for the strict gate:

```sh
scripts/check-github-ad-gate.py
```

The readiness script must report all required secrets present. It does not
prove that GitHub-hosted runners can reach the AD endpoints; an AD job's
preflight would check that from inside GitHub Actions. Treat strict readiness
as meaningful only when the endpoint secrets point at real AD services.

To check only the keytab secrets, without requiring live AD endpoints, run:

```sh
scripts/check-github-ad-gate.py --dry-run
```

To also check the self-hosted runner labels, pass
`--require-self-hosted-runner`.

Dispatch is unsupported in rskrb5-ng today. `--dispatch` reads
`.github/workflows/ci.yml` before any GitHub call. While the workflow's
`workflow_dispatch` lacks any of the inputs the helper passes (`integration`,
`test_ad`, `test_ad_dry_run`, `test_kpasswd`), it exits 2 and dispatches
nothing. Once an AD job and those inputs are restored, these commands dispatch
the dry-run (keytab secret shape only, no AD parity) and the strict job:

```sh
scripts/check-github-ad-gate.py --dry-run --dispatch --ref main
scripts/check-github-ad-gate.py --dispatch --ref main
```

`python3 scripts/check-github-ad-gate.py --self-test` checks both behaviours
against a stub `gh`.

## Failure Triage

Common external blockers:

- required secret missing or set to an empty value;
- GitHub-hosted runner cannot reach one or both KDCs on TCP `88`;
- endpoint secret is not `host:port`;
- keytab secret is not valid base64 or is not a complete MIT keytab;
- keytab principal, kvno, enctype, or password is stale relative to AD;
- required SPN or bidirectional trust is missing;
- RC4-HMAC is disabled for the resource-domain trust scenario;
- runner and domain-controller clocks are outside Kerberos skew tolerance.

If the readiness script stays red, keep `docs/gokrb5-parity.toml` and
`docs/gokrb5-parity.md` at `blocked-on-lab`.
