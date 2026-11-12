# Security

## Reporting

Do not post undisclosed vulnerabilities, exploit details, credentials or sensitive
debug logs in public issues. GitHub private vulnerability reporting is currently
disabled and this repository does not yet advertise a verified private reporting
channel. Maintainer approval is needed to choose and monitor that channel; this
document does not establish a response deadline, embargo or support commitment.
Public issues remain appropriate for non-sensitive bugs and documentation fixes.

## Versions and dependencies

No maintained-version matrix or security backport guarantee is currently declared.
Review the latest release notes and the dependency versions for your platform.
The plugin statically links native dependencies: updating the operating system
does not replace those embedded copies.

Each new release includes separately artifact-bound ZIP and DMG CycloneDX/SPDX
SBOMs. They are partial inventories, not a vulnerability assessment or a promise
that every component, supplier, license or acquisition origin is known.
See [evidence and verification](build/sbom/README.md) and
[dependency follow-up](build/sbom/SECURITY-REVIEW.md).

Future releases built with the hardened workflow publish GitHub build provenance
and SBOM attestations after final packaging. Existing releases do not acquire
reconstructed contemporaneous provenance. These attestations are distinct from
platform code signing; existing macOS signing/notarization is unchanged and no
new Windows signing coverage is claimed.
