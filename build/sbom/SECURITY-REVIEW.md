# Dependency and repository security follow-up

Reviewed 2026-11-12 against main commit
`cb612de` (v4.9.9 source) and the existing normalized archive inventory.
This is a bounded evidence review, not a product vulnerability assessment,
scanner clearance, VEX statement or compliance certification.

## Flagged native versions

`python3 build/sbom/archives.py verify` checks current bytes against the reviewed
manifest. Relevant repository archive evidence is:

| Archive | SHA-256 | Supported identity |
| --- | --- | --- |
| `a/libssh2.a` | `4798c04538ec4525872671eb2c0ef6b3c6acb7b2c30374f8338cec0b5324bbba` | Both macOS targets: `1.11.1_DEV` string |
| `lib/64/libssh2.lib` | `36ff95ef99d4bed6cf18df8d60efcc107ceb748c7515ceb354ce8a88de7909eb` | Windows: `1.11.1_DEV` string |
| `a/libiconv.a` | `d850040f3aac1742835f4fbf018b120735ad3f0f3154c8e56a7b4e53ef1d1333` | Both macOS targets: version object `1.16` |
| `lib/64/iconv.lib` | `b6ec6797d66824c6fd2076e56e1e9739319aa04f121f2879673fd1548f512822` | Windows: version object `1.18` |

These are archive hashes, not hashes of abstract logical packages or proof of
acquisition. Actual release incorporation requires target-specific linker
selection and final binary/container bindings. The separate debug libssh2
archive reports `1.11.0`; its presence does not make it a release dependency.

### libssh2

The `_DEV` suffix does not locate a source commit or prove an unreleased,
vulnerable build. Upstream's
[1.11.1 Git header](https://github.com/libssh2/libssh2/blob/a312b43325e3383c865a87bb1d26cb52e3292641/include/libssh2.h)
itself contains `1.11.1_DEV`. The same tag's
[release script](https://github.com/libssh2/libssh2/blob/a312b43325e3383c865a87bb1d26cb52e3292641/maketgz#L52-L60)
rewrites the version and timestamp for distributions. The official
[1.11.1 tarball](https://libssh2.org/download/libssh2-1.11.1.tar.gz) header
reports `1.11.1` and `Wed Oct 16 08:03:21 UTC 2024`.
This explains why Git-built and release-tarball banners can differ; it does not
establish which commit or patches produced our archives. Keep the observed
suffix in the SBOM rather than silently normalizing to the tarball version.

SFTP is a documented plugin feature. `4DPlugin-cURL.cpp` hands URLs and SSH
options to libcurl, so SSH-related dependencies cannot be dismissed as
unreachable solely because this is a curl wrapper. Conversely, selected archive
members and version banners alone cannot establish exploitability.
The upstream
[security policy](https://github.com/libssh2/libssh2/blob/e75fa9a539d21e82d4920c126662e36984e97d61/docs/SECURITY.md)
and [advisories](https://github.com/libssh2/libssh2/security/advisories) are
starting points, not proof of no vulnerabilities in this product.

Remaining work: recover exact source/acquisition and patch records for both
archives, correlate any applicable advisories to that code and build
configuration, and test the affected protocol paths before an affected or
not-affected conclusion. A controlled source rebuild/update needs separate
compatibility work; none was performed here.

### GNU libiconv

The platform difference is supported by reviewed defined-symbol/version-object
evidence, not a nearby header. `4DPlugin-cURL.cpp` directly calls `iconv_open`,
`iconv` and `iconv_close` in its conversion helpers; absence of a libcurl
banner is not evidence that the library is unused.

The [GNU project page](https://www.gnu.org/software/libiconv/) distinguishes the
LGPL libraries from the GPL command-line program. The
[upstream NEWS snapshot](https://github.com/arthenica/libiconv/blob/baaba39736e3b498e1597bf0e5e899b1f753fb01/NEWS)
records converter/behavior changes after 1.16 and a library license-version
change in 1.17. Those are upstream source facts, not verified license or
acquisition metadata for these prebuilt archives. In particular, do not assign
today's upstream license indiscriminately to both platforms.

Remaining work: recover source/configuration/patch/license records, review
relevant advisories against the exact converter code and caller inputs, and
exercise encoding compatibility before choosing a common version. Age or a
version mismatch alone proves neither vulnerability nor safety. No CVE
affected/not-affected assertion is made and no empty VEX is emitted.

## Repository controls

The repository is public. At review time, main was unprotected, no repository
rulesets existed, and private vulnerability reporting was disabled.
Dependabot alerts and automated security fixes, secret scanning and secret
push protection were enabled and re-read successfully. Non-provider secret
patterns and validity checks were not enabled. These settings are independent
of this branch's merge status; finding count is not a security clearance.

`.github/dependabot.yml` maintains SHA-pinned Actions and the SBOM Python tools.
It does not update vendored native archives or the OpenSSL/Brotli source pins;
those still require reviewed source/build evidence and native compatibility
checks. Security update availability depends on GitHub ecosystem/advisory
coverage and is not a native dependency assessment.

No branch protection, bypass policy or reporting/support commitment was
changed. Compatible next decisions for the maintainer:

- Choose and monitor a private reporting channel (GitHub private vulnerability
  reporting is currently off), and define any supported-version policy.
- Consider a main ruleset requiring pull requests, blocking deletion and
  non-fast-forward pushes. Decide whether the existing manual **Bump version**
  workflow may push directly, must use PRs, or needs a narrowly scoped bypass.
  Do not enable a rule that silently breaks that workflow.
- Choose required checks after inspecting their real contexts. Existing checks
  have path filters, so requiring them unconditionally can leave unrelated PRs
  pending. Decide on always-reported gates and administrator/bot bypasses first.

## Release controls

External Actions are pinned to resolved upstream commits within their existing
major versions; new attestation Actions are pinned separately. Dependabot
proposes pin updates for review rather than moving them during a build.
Only the separate attest/publish job receives `contents: write`,
`id-token: write` and `attestations: write`. Native builds remain read-only.
The publication job has no production signing secrets.

The final ZIP, stapled DMG and six validated sidecars are handed off once via
an immutable workflow artifact. All subsequent operations are read-only with
respect to those release files. Build provenance covers their exact bytes;
each container has its own CycloneDX and SPDX SBOM attestation. This does not
make prebuilt dependencies reproducible or establish their acquisition origin.
Production attestation issuance can only be confirmed on a future authorized
release; safe unsigned/historical validation does not issue release attestations.
v4.9.9 assets and tags must not be changed to backfill these claims.
