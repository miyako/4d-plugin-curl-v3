#!/usr/bin/env python3
"""Source-only version bumps and SHA-bound manual release preparation."""

import argparse
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys


PROJECT = Path("cURL.xcodeproj/project.pbxproj")
PLIST = Path("Info.plist")
SEMVER = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
TRAILER = "Co-authored-by: Copilot App <223556219+Copilot@users.noreply.github.com>"


def run(*args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()


def source_version(root=Path(".")):
    text = (root / PROJECT).read_text(encoding="utf-8")
    values = re.findall(r"\bMARKETING_VERSION\s*=\s*([^;]+);", text)
    if not values or any(not re.fullmatch(SEMVER, value) for value in values):
        raise ValueError("Missing or invalid Xcode MARKETING_VERSION")
    if len(set(values)) != 1:
        raise ValueError("Xcode marketing versions disagree")
    version = values[0]
    build_values = re.findall(r"\bCURRENT_PROJECT_VERSION\s*=\s*([^;]+);", text)
    if any(value != version for value in build_values):
        raise ValueError("Xcode build/release versions disagree")
    info = plistlib.loads((root / PLIST).read_bytes())
    if info.get("CFBundleShortVersionString") not in (version, "$(MARKETING_VERSION)"):
        raise ValueError("Info.plist and Xcode release versions disagree")
    build = info.get("CFBundleVersion")
    if build is not None:
        expected = {"$(MARKETING_VERSION)", version}
        if build_values:
            expected.add("$(CURRENT_PROJECT_VERSION)")
        if build not in expected:
            raise ValueError("Info.plist build version disagrees with source version")
    return version


def bump_source(mode, root=Path(".")):
    current = source_version(root)
    parts = list(map(int, current.split(".")))
    index = {"major": 0, "minor": 1, "patch": 2}[mode]
    parts[index] += 1
    parts[index + 1:] = [0] * (2 - index)
    version = ".".join(map(str, parts))
    project = root / PROJECT
    text = project.read_text(encoding="utf-8")
    text = re.sub(r"\b(MARKETING_VERSION|CURRENT_PROJECT_VERSION)(\s*=\s*)" + SEMVER + ";",
                  lambda match: match[1] + match[2] + version + ";", text)
    info = plistlib.loads((root / PLIST).read_bytes())
    changed = False
    for key in ("CFBundleShortVersionString", "CFBundleVersion"):
        if key in info and not info[key].startswith("$("):
            info[key] = version
            changed = True
    project.write_text(text, encoding="utf-8")
    if changed:
        (root / PLIST).write_bytes(plistlib.dumps(info))
    if source_version(root) != version:
        raise ValueError("Bumped source version failed verification")
    return version


def verify_checkout(sha):
    if not re.fullmatch(r"[a-f0-9]{40}", sha) or run("git", "rev-parse", "HEAD") != sha:
        raise ValueError("Checkout does not match the selected immutable commit")
    if run("git", "status", "--porcelain", "--untracked-files=normal"):
        raise ValueError("Selected checkout must be clean")


def branch_ref(ref):
    if not ref.startswith("refs/heads/"):
        raise ValueError("Select a branch, not a tag, in Run workflow")
    run("git", "check-ref-format", ref)


def remote_sha(ref):
    lines = run("git", "ls-remote", "--refs", "origin", ref).splitlines()
    if len(lines) != 1 or lines[0].split()[1] != ref:
        raise ValueError("Selected remote branch is missing or ambiguous")
    return lines[0].split()[0]


def api_optional(endpoint):
    result = subprocess.run(["gh", "api", endpoint], text=True, capture_output=True)
    if result.returncode:
        if "(HTTP 404)" in result.stderr:
            return None
        raise ValueError("GitHub metadata lookup failed: " + result.stderr.strip())
    return json.loads(result.stdout)


def publication_check(repository, tag, sha):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Invalid repository identity")
    if not re.fullmatch("v" + SEMVER, tag):
        raise ValueError("Invalid release tag; whitespace is not allowed")
    if api_optional(f"repos/{repository}/releases/tags/{tag}") is not None:
        raise ValueError(f"Release {tag} already exists; bump the version rather than overwrite it")
    ref = api_optional(f"repos/{repository}/git/ref/tags/{tag}")
    if ref is not None:
        obj = ref["object"]
        while obj["type"] == "tag":
            obj = json.loads(run("gh", "api", f"repos/{repository}/git/tags/{obj['sha']}"))["object"]
        if obj["type"] != "commit" or obj["sha"] != sha:
            raise ValueError(f"Tag {tag} already refers to another commit; bump the version")
    return ref


def preflight(sha, ref, repository):
    branch_ref(ref)
    verify_checkout(sha)
    version = source_version()
    publication_check(repository, "v" + version, sha)
    return version


def bump_branch(sha, ref, mode):
    branch_ref(ref)
    verify_checkout(sha)
    if remote_sha(ref) != sha:
        raise ValueError("Selected branch moved since dispatch")
    version = bump_source(mode)
    run("git", "add", "--", str(PROJECT), str(PLIST))
    run("git", "-c", "user.name=github-actions[bot]", "-c",
        "user.email=github-actions[bot]@users.noreply.github.com", "commit",
        "-m", f"chore: bump version to {version}", "-m", TRAILER)
    new = run("git", "rev-parse", "HEAD")
    if run("git", "rev-list", "--parents", "-n", "1", new) != f"{new} {sha}":
        raise ValueError("Version bump must have the selected commit as its only parent")
    if remote_sha(ref) != sha:
        raise ValueError("Selected branch moved during bump; no push performed")
    run("git", "-c", "push.followTags=false", "push", "--no-follow-tags",
        "origin", f"{new}:{ref}")
    if remote_sha(ref) != new:
        raise ValueError("Remote branch no longer matches the pushed bump")
    return version


def publish(sha, repository, version, paths):
    if run("git", "rev-parse", "HEAD") != sha or source_version() != version:
        raise ValueError("Publication source/version differs from the selected build")
    if not paths or any(not path.is_file() for path in paths):
        raise ValueError("Missing release files; publication stopped")
    tag = "v" + version
    existing = publication_check(repository, tag, sha)
    if existing is None:
        run("gh", "api", "--method", "POST", f"repos/{repository}/git/refs",
            "-f", f"ref=refs/tags/{tag}", "-f", f"sha={sha}")
    # create, never upload --clobber: an existing release is an explicit failure.
    run("gh", "release", "create", tag, "--repo", repository, "--verify-tag",
        "--title", tag, "--generate-notes", *map(str, paths))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("read")
    bump = commands.add_parser("bump")
    bump.add_argument("mode", choices=("patch", "minor", "major"))
    for command in (bump, commands.add_parser("preflight")):
        command.add_argument("--sha", required=True)
        command.add_argument("--ref", required=True)
    publication = commands.add_parser("publish")
    publication.add_argument("--sha", required=True)
    publication.add_argument("--version", required=True)
    publication.add_argument("files", nargs="+", type=Path)
    args = parser.parse_args(argv)
    if args.command == "publish":
        publish(args.sha, os.environ["GITHUB_REPOSITORY"], args.version, args.files)
        return
    if args.command == "bump":
        version = bump_branch(args.sha, args.ref, args.mode)
    elif args.command == "preflight":
        version = preflight(args.sha, args.ref, os.environ["GITHUB_REPOSITORY"])
    else:
        version = source_version()
    print(version)
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            output.write(f"version={version}\ntag=v{version}\n")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
            summary.write(f"### Source version: {version}\n")
            if args.command == "bump":
                summary.write("Source updated only. Run **Build** separately on the updated branch.\n")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print(f"Version/release stopped: {error}", file=sys.stderr)
        sys.exit(1)
