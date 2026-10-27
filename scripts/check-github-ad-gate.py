#!/usr/bin/env python3
"""Check GitHub-side readiness for the strict AD integration gate.

The fork's `.github/workflows/ci.yml` has no AD job and its `workflow_dispatch`
declares no inputs (the upstream `clelange/rskrb5` workflow had both), so
`--dispatch` refuses to run until ci.yml declares every input in
`DISPATCH_INPUTS`; the secret readiness check works either way.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ENDPOINT_SECRETS = [
    "TEST_AD_USER_KDC_ADDR",
    "TEST_AD_RESOURCE_KDC_ADDR",
    "TEST_AD_USER_ADMIN_ADDR",
    "TEST_AD_RESOURCE_ADMIN_ADDR",
]

KEYTAB_SECRETS = [
    "TEST_AD_TESTUSER1_KEYTAB_BASE64",
    "TEST_AD_TESTUSER2_KEYTAB_BASE64",
    "TEST_AD_TESTUSER3_KEYTAB_BASE64",
    "TEST_AD_SYSHTTP_KEYTAB_BASE64",
]

REQUIRED_RUNNER_LABELS = {"self-hosted", "linux", "x64", "rskrb5-ad"}

# The `workflow_dispatch` inputs `--dispatch` passes to ci.yml.
DISPATCH_INPUTS = ("integration", "test_ad", "test_ad_dry_run", "test_kpasswd")

CI_WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml"


def declared_dispatch_inputs(workflow: str) -> set[str]:
    """Return the input names under `on: workflow_dispatch: inputs:` of a workflow."""
    inputs: set[str] = set()
    in_dispatch = False
    in_inputs = False
    for line in workflow.splitlines():
        content = line.lstrip(" ")
        if not content or content.startswith("#"):
            continue
        indent = len(line) - len(content)
        if indent == 0:
            in_dispatch = in_inputs = False
        elif indent == 2:
            in_dispatch = content.rstrip() == "workflow_dispatch:"
            in_inputs = False
        elif indent == 4:
            in_inputs = in_dispatch and content.rstrip() == "inputs:"
        elif indent == 6 and in_inputs and content.rstrip().endswith(":"):
            inputs.add(content.rstrip()[:-1])
    return inputs


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    parser = argparse.ArgumentParser(
        description="Check required GitHub Actions secrets for test_ad=true."
    )
    parser.add_argument(
        "--dispatch",
        action="store_true",
        help="Dispatch CI when all prerequisites for the selected mode are ready.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Check or dispatch the non-live AD keytab-secret dry run. "
            "Only keytab secrets are required, and AD parity is not proven."
        ),
    )
    parser.add_argument(
        "--ref",
        default="main",
        help="Git ref to dispatch when --dispatch is used. Defaults to main.",
    )
    parser.add_argument(
        "--require-self-hosted-runner",
        action="store_true",
        help=(
            "Also require an online self-hosted runner with the legacy "
            "rskrb5-ad labels. The default workflow uses ubuntu-latest."
        ),
    )
    args = parser.parse_args()

    if args.dispatch:
        # Refuse before any GitHub call: dispatching inputs ci.yml does not
        # declare fails on GitHub, or runs the ordinary push jobs instead.
        missing_inputs = [
            name
            for name in DISPATCH_INPUTS
            if name not in declared_dispatch_inputs(CI_WORKFLOW.read_text(encoding="utf-8"))
        ]
        if missing_inputs:
            print(
                "--dispatch is unsupported: .github/workflows/ci.yml declares no "
                "workflow_dispatch input(s) " + ", ".join(missing_inputs) + " and has no "
                "AD job. Restore the AD job and its inputs first; see "
                "docs/github-ad-gate-setup.md.",
                file=sys.stderr,
            )
            return 2

    repo = gh_json(["repo", "view", "--json", "nameWithOwner"])["nameWithOwner"]
    print(f"Repository: {repo}")

    required_secrets = KEYTAB_SECRETS if args.dry_run else ENDPOINT_SECRETS + KEYTAB_SECRETS
    missing_secrets = sorted(set(required_secrets) - actions_secret_names())
    if missing_secrets:
        print("Missing Actions secrets:")
        for name in missing_secrets:
            print(f"  - {name}")
    else:
        print("Actions secrets: all required AD secrets are present.")

    if args.dry_run:
        print(
            "Mode: AD keytab-secret dry run. Endpoint secrets and live AD "
            "reachability are not checked."
        )
    else:
        print("Mode: strict live AD gate.")

    errors = []
    if missing_secrets:
        errors.append("required Actions secrets are missing")

    if args.require_self_hosted_runner:
        matching_runners, runners = ad_runner_inventory(repo)
        if matching_runners:
            print("AD runners:")
            for runner in matching_runners:
                labels = ", ".join(sorted(runner["labels"]))
                print(f"  - {runner['name']} ({runner['status']}, labels: {labels})")
        elif runners:
            print("Registered self-hosted runners:")
            for runner in runners:
                labels = ", ".join(sorted(runner["labels"]))
                print(f"  - {runner['name']} ({runner['status']}, labels: {labels})")
            print(
                "No online runner has the complete required label set: "
                + ", ".join(sorted(REQUIRED_RUNNER_LABELS))
            )
        else:
            print("No self-hosted runners are registered for this repository.")
            print(
                "Required runner labels: " + ", ".join(sorted(REQUIRED_RUNNER_LABELS))
            )

        if not matching_runners:
            if runners:
                errors.append(
                    "no online self-hosted runner has the complete rskrb5-ad label set"
                )
            else:
                errors.append("no self-hosted runner is registered")
    else:
        print("Runner: GitHub-hosted ubuntu-latest; no self-hosted runner required.")

    if errors:
        sys.stdout.flush()
        print("\nGitHub AD gate is not ready:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        print(
            "\nSee docs/github-ad-gate-setup.md for the runner mode and secret setup.",
            file=sys.stderr,
        )
        return 1

    print("GitHub AD gate is ready.")
    if args.dispatch:
        test_ad = "false" if args.dry_run else "true"
        test_ad_dry_run = "true" if args.dry_run else "false"
        gh(
            [
                "workflow",
                "run",
                "ci.yml",
                "--ref",
                args.ref,
                "--field",
                "integration=false",
                "--field",
                f"test_ad={test_ad}",
                "--field",
                f"test_ad_dry_run={test_ad_dry_run}",
                "--field",
                "test_kpasswd=false",
            ]
        )
        dispatched_input = "test_ad_dry_run=true" if args.dry_run else "test_ad=true"
        print(f"Dispatched ci.yml with {dispatched_input} on {args.ref}.")
    return 0


def actions_secret_names() -> set[str]:
    result = gh_json(["api", "repos/:owner/:repo/actions/secrets"])
    return {secret["name"] for secret in result.get("secrets", [])}


def ad_runner_inventory(
    repo: str,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    result = gh_json(["api", f"repos/{repo}/actions/runners"])
    inventory = []
    runners = []
    for runner in result.get("runners", []):
        labels = {label["name"] for label in runner.get("labels", [])}
        entry = {
            "name": runner["name"],
            "status": runner["status"],
            "labels": labels,
        }
        inventory.append(entry)
        if REQUIRED_RUNNER_LABELS.issubset(labels) and runner.get("status") == "online":
            runners.append(entry)
    return runners, inventory


def gh_json(args: list[str]) -> dict[str, object]:
    output = gh(args)
    return json.loads(output)


def gh(args: list[str]) -> str:
    completed = subprocess.run(
        ["gh", *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout


GH_STUB = """#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ["GH_STUB_LOG"], "a", encoding="utf-8") as log:
    log.write(" ".join(args) + "\\n")
if args[:2] == ["repo", "view"]:
    print(json.dumps({"nameWithOwner": "andrico21/rskrb5-ng"}))
elif args[:1] == ["api"] and args[1].endswith("actions/secrets"):
    names = os.environ["GH_STUB_SECRETS"].split()
    print(json.dumps({"secrets": [{"name": name} for name in names]}))
elif args[:2] == ["workflow", "run"]:
    pass
else:
    sys.exit(1)
"""

CI_WITH_AD_INPUTS = """name: CI
on:
  push:
    branches: [main]
  workflow_dispatch:
    inputs:
      integration:
        type: boolean
      test_ad:
        type: boolean
      test_ad_dry_run:
        type: boolean
      test_kpasswd:
        type: boolean
jobs:
  test:
    runs-on: ubuntu-latest
"""


def run_in_scratch_repo(ci_text: str, argv: list[str]) -> tuple[int, str, list[str]]:
    """Run a copy of this script beside `ci_text` as .github/workflows/ci.yml,
    with a stub `gh` first on PATH; return (exit code, stderr, gh calls)."""
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        (root / "scripts").mkdir()
        (root / ".github" / "workflows").mkdir(parents=True)
        (root / ".github" / "workflows" / "ci.yml").write_text(ci_text, encoding="utf-8")
        script = root / "scripts" / Path(__file__).name
        shutil.copyfile(__file__, script)
        stub_dir = root / "bin"
        stub_dir.mkdir()
        stub = stub_dir / "gh"
        stub.write_text(GH_STUB, encoding="utf-8")
        stub.chmod(0o755)
        log = root / "gh.log"
        log.touch()
        env = dict(os.environ)
        env["PATH"] = f"{stub_dir}{os.pathsep}{env.get('PATH', '')}"
        env["GH_STUB_LOG"] = str(log)
        env["GH_STUB_SECRETS"] = " ".join(ENDPOINT_SECRETS + KEYTAB_SECRETS)
        completed = subprocess.run(
            [sys.executable, str(script), *argv],
            cwd=root,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        calls = log.read_text(encoding="utf-8").splitlines()
        return completed.returncode, completed.stderr, calls


def self_test() -> int:
    """Dispatch is refused while ci.yml lacks the AD inputs and allowed once they exist."""
    failures = []
    fork_ci = (Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    for argv in (["--dispatch"], ["--dry-run", "--dispatch"]):
        code, stderr, calls = run_in_scratch_repo(fork_ci, argv)
        dispatched = [call for call in calls if call.startswith("workflow run")]
        if code == 0 or dispatched:
            failures.append(
                f"{' '.join(argv)} against the fork ci.yml: exit {code}, gh calls {dispatched}; "
                "expected a refusal without dispatch"
            )
        elif "workflow_dispatch" not in stderr:
            failures.append(f"{' '.join(argv)}: the refusal does not name workflow_dispatch: {stderr!r}")
    code, stderr, calls = run_in_scratch_repo(CI_WITH_AD_INPUTS, ["--dry-run", "--dispatch"])
    dispatched = [call for call in calls if call.startswith("workflow run")]
    if code != 0 or len(dispatched) != 1:
        failures.append(
            f"--dry-run --dispatch with the AD inputs declared: exit {code}, gh calls {dispatched}, "
            f"stderr {stderr!r}; expected one dispatch"
        )
    for failure in failures:
        print(f"self-test FAIL: {failure}", file=sys.stderr)
    if failures:
        return 1
    print("self-test: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
