# Candidate source and user-relink materials

**Original source/relink evidence, not a legal-compliance certification.**
When supplied with a release, `../release-binding.json` joins that release to
these unchanged original materials. `inventory.json` still describes
its exact original unsigned ZIP, not the hash or contents of this source kit.
Release authorization does not retroactively change original producer records.

## What is delivered

`reference/unsigned-native.zip` is the exact original unsigned cross-platform
candidate ZIP bound by `inventory.json`. It contains the reference bundle,
not a newly adopted production build. Its Mac universal and Windows x64
executables are independently joined to all three inventory targets.

`platforms/macos-universal` and `platforms/windows-x86_64` retain the immutable
selected-only source/object kits, actual selected archives and reference
plugin binaries. Their original records, source/patch/build recipes, product
sources and LGPL library source deliveries remain unchanged. The Mac kit
contains both CPU object sets. The Windows kit contains x64 objects.

`notices/NOTICES.txt` and its retained inputs preserve the inventory's actual
primary, additional, embedded and alternative-license notices. Native LF and
CRLF license variants retain their distinct hashes. Root MIT permission for
project-owned code does not relicense third-party code. Unknown historical
proxy/modman archive revisions and the candidate's unknown numeric libmodman
version remain unknown.

`providers/` contains the exact original referenced OpenSSL/Brotli records and
their complete recorded source/compiler/object/archive closure. This is a
derived subset, not a complete original installation: installed command-line
programs are excluded. Whole-provider audit records can require an unselected
source-built encoder archive. These audit files are **not additional selected
plugin dependencies**; do not add provider directories to linker search paths.
Ancillary source tools retain their own license files; their presence is not
a claim that their code or license applies to the linked library.

`tools/` supplies the current tracked source tools and their project license.
Old tool snapshots embedded in immutable kits remain evidence, not the current
generic user interface. No Apple SDK, MSVC, Windows SDK, CRT or system library
is redistributed. Their paths and hashes in original records are prerequisites,
not bundled proprietary materials.

## Inspect before use

From this directory, using Python 3:

```sh
python3 tools/build/dependencies/relink_review_delivery.py \
  --inspect-only --output .
```

Inspection does not invoke a compiler or initialize 4D/plugin code. It checks
exact file bytes, all selected archive/binary/slice joins, complete notices and
every retained provider source/compiler/archive join. It does not authenticate
an arbitrary rewritten manifest; verify the separately supplied artifact hash
and original CI producer information through a trusted channel.

## Rebuild or replace a library

Keep the original kit immutable. Work in a fresh external directory. Retain the
library's full source, original license/copyright notices, dated modifications,
patches, generated configuration, commands and resulting archive/object hashes.
Use the delivered corresponding library sources and measured recipe rather
than guessing a version from a historical archive filename.

For the pinned GNU/proxy library source builders and their platform-specific
prerequisites, use `tools/build/dependencies/README.md` and the recipe/source
records under each platform's `library-materials/`. The default demonstration
drivers require their own fixed probes; their inspectors are not general user
modification validators. The generic link commands below do not require those
probes or a maintainer key.

GNU configure output paths must not contain whitespace. The kit, subsequent
raw-link output and inspection paths can contain spaces. Use separate thin
Mac archives for arm64 and x86_64, or a release-static-CRT Windows x64 archive.
Preserve the intended deployment target, compiler ABI and library interfaces.
A successful raw link alone does not establish those properties.

## Link a modified Mac library

Install a compatible licensed Xcode/Command Line Tools and SDK, and select it
with normal developer-tool configuration. The generic user path records its
actual toolchain separately; it does not rewrite the original producer record
or relax the original strict byte-identical replay.

```sh
python3 tools/build/dependencies/user_relink_macos.py replay \
  --kit platforms/macos-universal --output "/user/fresh link" \
  --replace-arm64 "a/libiconv.a=/user/arm64/libiconv.a" \
  --replace-x86-64 "a/libiconv.a=/user/x86_64/libiconv.a"
python3 tools/build/dependencies/user_relink_macos.py inspect \
  --kit platforms/macos-universal --output "/user/fresh link"
```

Repeat options for other selected archive paths. At least one replacement is
required; the other CPU may retain original archives. The driver preserves raw
argument/search order and checks original public section symbols against both
the user-toolchain baseline and modified slices. It creates a universal `cURL`,
not an installed or newly signed production bundle.

## Link a modified Windows library

Use the original recorded compatible x64 MSVC linker, Windows SDK and release
static CRT environment. The Windows raw linker checks the exact recorded
system/linker inputs; it does not silently substitute another SDK/CRT.

```powershell
python tools/build/dependencies/user_relink_windows.py replay `
  --kit platforms/windows-x86_64 --output "C:/user/fresh link" `
  --replace "lib/64/iconv.lib=C:/user/edited/iconv.lib"
python tools/build/dependencies/user_relink_windows.py inspect `
  --kit platforms/windows-x86_64 --output "C:/user/fresh link"
```

This retains raw link order and original plugin exports without forced
demonstration symbols. The output is a user-created `cURL.4DX`, not a production
release or evidence of arbitrary replacement compatibility.

## Static redistribution and remaining review

The proposed static-distribution route is delivery of the actual applicable
LGPL library sources, modifications and build scripts together with the
non-library application source/object inputs needed for user relinking.
Recipients must be able to modify/relink the libraries and debug those
modifications without a maintainer signing key. Any distribution terms must
permit the required modifications and reverse engineering for that debugging.
Notices alone, a source URL alone, or schema-valid SBOMs do not satisfy this
route. The complete terms in this delivery control; this paragraph is not a
substitute for reviewing their applicable versions and alternatives.

Before public distribution, review all source/object redistribution terms,
the original SDK interface/source license, ancillary source-tool terms and
practical availability of the matching proprietary toolchains. Preserve the
proxy PAC source's full alternative notice and chosen LGPL route rather than
discarding the alternative text. Do not blanket-relicense the plugin's
third-party inputs under the root MIT license.

## Optional operator-run installation and trust checks

No automation in this delivery loads 4D or the plugin. Native link/conversion
evidence is not host-installation, older-OS, ABI or application behavior proof.
Manual 4D testing is not a release gate. Automated source/archive/link/container
checks remain mandatory; they do not establish host-runtime or older-OS behavior.

Use a licensed compatible 64-bit 4D host and a disposable copy of the repository
test project, never a production database. The test project file is
`test/Project/test.4DProject`; its `Plugins` directory belongs beside `Project`.
Retain one cross-platform `cURL.bundle` with `Contents/MacOS/cURL` universal and
`Contents/Windows64/cURL.4DX` x64. Replace only the matching executable in a
separate user-owned candidate bundle and retain the other platform executable
and resources. Check architectures and user output hashes before installing.
Start from the verified `reference/unsigned-native.zip`, not a per-platform
build kit's working bundle; those working bundles are retained build inputs
and are not substitutes for the assembled cross-platform reference.

On Mac, verify the host's supported plugin-loading/trust requirements and
library-validation entitlement. A new executable invalidates old signing
resources; use a separate user-owned bundle and supported local/ad-hoc signing
or trust procedures, not the maintainer's Developer ID credentials. Do not
disable Gatekeeper/SIP, alter the installed host, or broadly strip quarantine.
On Windows, confirm an interactive compatible 4D host and required user trust
are available; no Authenticode/Azure setup is supplied or assumed.

Record host/OS versions, install location, local signing/trust steps, loaded
candidate hash, loader result and narrowly selected functional results.
`TEST_version_info` overwrites the clipboard; do not run it unintentionally.
An operator must deliberately choose safe test methods and preserve the report.
The delivery's inspectors never claim these optional host checks passed.
