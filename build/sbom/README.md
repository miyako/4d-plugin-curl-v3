# Release SBOMs and native dependency traceability

The release workflow adds three **sidecars per final distributed container**:
`cURL-VERSION.zip.cdx.json` (CycloneDX 1.6 JSON),
`cURL-VERSION.zip.spdx.json` (SPDX 2.3 JSON), and
`cURL-VERSION.zip.inventory.json` (the shared evidence inventory).
The DMG gets the same three suffixes. They are generated **after signing,
notarization and DMG stapling**, without changing the plugin or either package.
Each document binds its root to the container's filename and SHA-256, with
plugin name, release version and supplier (Keisuke Miyako, from `LICENSE`).
The version must match the packaged `CFBundleShortVersionString`.

Both current containers contain macOS **and Windows**, even though the DMG is
macOS-friendly. Each is inspected independently; the ZIP is not used as a
proxy for DMG contents. The inventory reads the plugin's universal Mach-O
headers and PE32+ header, requiring macOS arm64, macOS x86_64 and Windows
x86_64. Each target has a separate component identity and evidence. macOS
records both the full signed binary hash and the analyzed slice hash;
Windows records its PE binary hash. CycloneDX also exposes `release:target`
properties. SPDX stores the same structured evidence as JSON in package
descriptions.

## Evidence and limits

This is deliberately **partial**, not a completeness or vulnerability-free
claim. There are three separate evidence classes:

1. **Analyzed binary observations:** narrow identifying-string rules for curl,
   OpenSSL, libssh2 and zlib, applied separately to each architecture's actual
   bytes. Versions retain suffixes such as `1.11.1_DEV`. Each observation
   records the matched text and offset relative to the analyzed slice/PE.
   Conflicting versions, absent curl identification, unsupported binary
   layouts, duplicate ZIP members and version mismatches fail explicitly.
   A marker establishes an observation, not runtime verification, feature
   availability or a complete dependency graph.
2. **Hash-bound native archives:** `native-archives.json` inventories every
   vendored `a/*.a` and `lib/64/**/*.lib`, including unused/debug alternatives.
   Each SHA-256 binds per-target identities to narrow identifying strings in
   that archive's bytes, not nearby headers or bare version numbers. Universal
   archive headers establish macOS targets; the Windows directory establishes
   intended x64 use, not a full COFF-member architecture audit. Unidentified
   archives remain inventoried with empty identities and explicit unknown
   acquisition origin/license/PURL. This is not reconstructed historical
   acquisition provenance.
3. **Build-derived inputs and selection:** future release builds capture declared
   Xcode framework-phase archives and MSBuild `Release|x64` libraries, the
   available repository-relative archive hashes, unresolved declarations,
   source checkout commit and configuration-file hashes, plus per-architecture
   Apple linker maps or MSVC `/MAP /VERBOSE:LIB` diagnostics. These records are
   bound to the exact packaged binary hash. The existing pinned Brotli build
   additionally records the version from its source `c/common/version.h`,
   source commit, license-file hash and hashes of its three newly built archives.
   OpenSSL records equivalent source/version/license evidence, configuration and
   installed archive hashes separately per architecture, then hashes the merged
   universal archives. Cached OpenSSL outputs must carry their original build
   records and pass source/configuration/archive verification on reuse; an
   unrecorded old cache is not retroactively assigned today's checkout identity.
   Consuming jobs verify source-built hashes against the actual candidate inputs.

Known identities are promoted into ordinary versioned CycloneDX components and
SPDX packages only when an exact-hash archive has **selected member evidence**.
Source-built Brotli and OpenSSL expose their supported MIT/Apache-2.0 licenses,
upstream locations and PURLs as standard fields. Matching binary observations
are merged into the same target package; version conflicts fail. An unselected
archive does not become an incorporated component. Unknown selected archives
remain useful hash/path/member evidence without an invented package version.
Target-to-package CycloneDX `dependsOn` and SPDX `DEPENDS_ON` edges mean
build-supported member selection, not an invented transitive dependency graph.
Archive checksums are evidence about archives, not falsely attached as the hash
of a logical library package.

The checked-in linker declarations still mention libraries beyond the six
dependencies listed in `build/build-libcurl-macos.sh`, including QUIC/HTTP3,
IDN and legacy proxy/LDAP inputs. That script is not treated as an authoritative
manifest of the released binary. Windows' existing absolute developer-machine
library search directories are **not removed or reordered**. A repository file
beside a declaration is a candidate, not proof it won the search. Actual resolved
paths in diagnostics determine selection; ambiguous basename-only map entries
must not silently select a repository file. External/system libraries can remain
unresolved or outside the verified manifest. Their paths/evidence limitations
remain in the inventory.

Apple object tables establish archive-member selection; live and dead-stripped
symbol sections are distinguished. MSVC verbose output establishes member loads;
map symbol attribution is partial, especially for COMDAT/LTCG. A selected member
can be completely stripped, or inlined under LTO with no surviving attributed
symbol. Thus a live symbol is positive attribution, **not** exact retained bytes,
and absence of live attributed symbols is **not** proof of absence. Raw maps/logs
are hashed and retained as CI artifacts for audit. These diagnostics add
observability; no force-load, whole-archive or link-order changes are introduced.

nghttp2 and Brotli, among others, can lack sufficiently identifying version
strings even when statically incorporated. Bare version numbers, header
versions and printf templates are not enough to assign a binary component
version. Static linking and dead stripping can also hide libraries entirely.
Unverified dependency licenses, PURLs and suppliers are not inferred. SPDX uses
`NOASSERTION`; CycloneDX omits those fields and declares an `incomplete`
composition. No complete dependency graph is asserted. SPDX `CONTAINS`
relationships identify scoped observations rather than dependency edges.
OS frameworks/libraries, CRT/toolchain, 4D SDK, embedded source (such as
`ftpparse.c`) and non-code resources are not exhaustively inventoried.

The reader never loads the plugin, calls its initialization, or executes
distributed code. ZIP members are read without extraction; DMGs are mounted
read-only with browsing/auto-opening disabled and detached afterward.
No binary is uploaded to an analysis service. Schema downloads only fetch
public, commit-pinned official specifications.

## Safe manual proof of concept

Run **Release SBOM proof of concept** (`sbom.yml`) against an existing release
tag, default `v4.9.6`. It only downloads the two containers, runs tests and
validation, and uploads six JSON files as a workflow artifact
`release-sbom-poc`. Its token has read-only repository permissions. It never
builds, signs, creates a release or uploads/replaces release assets. The same
path runs for relevant pull-request changes. Old releases have no contemporaneous
build records, so this path emits binary observations only, not reconstructed
build provenance from today's checkout.

The separate **Unsigned native linker trace** workflow builds unsigned plugins on
both platforms and captures real linker diagnostics without signing,
notarization, publishing or loading the plugin. It is the safe path for
validating current build traceability, unlike the read-only historical workflow.

## Refreshing the archive manifest

After acquiring/updating vendored archives through the project's existing
process, run and review:

```sh
python3 build/sbom/archives.py refresh
python3 build/sbom/archives.py verify
git diff -- build/sbom/native-archives.json
```

Commit the reviewed manifest alongside archive updates. `refresh` only derives
hashes, target evidence and narrow archive markers; it does not invent an
upstream download URL or license. To improve an unknown identity, first obtain
an attributable source/build record or a trustworthy package manifest whose
archive hash matches. Do not copy a version from a header or infer it from a
filename. Release collection rejects an unreviewed archive hash unless it is
explicitly covered by the freshly built Brotli/OpenSSL provenance. Source-built
overrides do not rewrite the checked-in vendored manifest. Historical analysis
without build evidence never consults today's manifest.

Local equivalent (Python 3.10+, `gh`; DMG inspection requires macOS):

```sh
python3 -m venv /tmp/curl-sbom-venv
/tmp/curl-sbom-venv/bin/pip install -r build/sbom/requirements.txt
gh release download v4.9.6 --repo miyako/4d-plugin-curl-v3 --dir /tmp/curl-assets \
  --pattern cURL-4.9.6.zip --pattern cURL-4.9.6.dmg
/tmp/curl-sbom-venv/bin/python -m unittest discover -s build/sbom -p 'test_*.py'
/tmp/curl-sbom-venv/bin/python build/sbom/generate.py generate \
  --version 4.9.6 --output /tmp/curl-sbom \
  /tmp/curl-assets/cURL-4.9.6.zip /tmp/curl-assets/cURL-4.9.6.dmg
/tmp/curl-sbom-venv/bin/python build/sbom/validate.py \
  --version 4.9.6 --output /tmp/curl-sbom --schema-dir /tmp/curl-sbom-schemas \
  /tmp/curl-assets/cURL-4.9.6.zip /tmp/curl-assets/cURL-4.9.6.dmg
```

ZIP-only analysis also works off macOS. Validation downloads official
CycloneDX 1.6 and SPDX 2.3 schemas at immutable upstream commits into the given
schema cache, including CycloneDX's referenced license/signature schemas.
Python `jsonschema` checks both formats. Semantic checks additionally verify
root supplier/version, artifact and binary hashes, known curl identity,
per-target distinctions, cross-format equivalence, evidence preservation,
and agreement with a fresh read of the actual containers.

The regression tests use deliberately different curl versions in synthetic
target binaries, reject stale evidence and tampered document hashes/versions,
and check that unidentifiable versions are not guessed.

## Demonstrated v4.9.6 observations

Both real released containers produce three targets and 12 native version
observations apiece:

| Target | curl | OpenSSL | libssh2 | zlib identifying string |
|---|---|---|---|---|
| macOS arm64 | 8.21.0 | 3.5.8 | 1.11.1_DEV | 1.3.2 |
| macOS x86_64 | 8.21.0 | 3.5.8 | 1.11.1_DEV | 1.3.2 |
| Windows x86_64 | 8.21.0 | 3.5.8 | 1.11.1_DEV | 1.3.1 |

| Asset | SHA-256 |
|---|---|
| `cURL-4.9.6.zip` | `0f6ea37bf28aa89325360279c9e16ad908c42e98933bfb144fb6c8f7cc2330df` |
| `cURL-4.9.6.dmg` | `9208a453bc00f220ff94ba154849335af33b0d02d95b86effc6f43a81f2c4ee8` |

These are observed strings, not a claim that one library version is the only
copy present. In particular, the Windows binary also has bare `1.3.2` and
`1.70.0` strings; neither overrides the identifying zlib marker or establishes
an nghttp2 version.

## Release integration

Static linking, normal local project settings, signing, notarization and packaging
remain unchanged. Workflow-only linker settings add maps/diagnostics.
Brotli's existing workflow artifact carries its provenance JSON file.
Windows and macOS record their declarations and selections after linking
(macOS binary binding after signing).
The packaging job requires both platform records and verifies their binary
hashes against **each** container before publishing sidecars through the existing
release upload step. Generation or validation failures stop publication instead
of uploading misleading documents. No new signing secrets are needed.

Release jobs check out the SBOM scripts separately from the workflow revision,
so manual builds of older tags do not require scripts in that old source tree.
This PoC does not backfill or overwrite historical release assets. The
SBOM-only workflow is the safe way to analyze an already-published release.
No full signed release was triggered to demonstrate this change.

## Unsigned native linker diagnostics

`native-trace.yml` is a read-only PR/manual workflow. It reuses the source-built
Brotli job, builds static OpenSSL from source on both runners, then builds the
actual plugin with diagnostic settings. It never loads/initializes the plugin,
signs, notarizes, publishes, or triggers the release workflow. A follow-on job
combines the unsigned builds into test ZIP/DMG containers and validates all six
documents against official schemas and actual artifact/binary hashes. It requires
selected source-built Brotli/OpenSSL packages with standard license/PURL fields,
and proves that Windows zlib comes from `zlib.lib`, not the unused `zs.lib`.
Its artifacts contain raw maps/logs, pre-link candidate hashes, and per-target
link evidence bound to the unsigned binary hash. These are build diagnostics,
not evidence that a signed release has already been tested.

For release integration (including source checkouts of old tags), take the
diagnostic configuration files from the workflow/tooling revision, not the
source tag. No project edits are required. On macOS, create the destination
directory before building and append these options to the existing invocation:

```sh
mkdir -p "$PWD/native-trace"
xcodebuild -project cURL.xcodeproj -target cURL -configuration Default \
  -xcconfig "$PWD/sbom-tools/build/sbom/diagnostics.xcconfig" \
  "NATIVE_TRACE_DIRECTORY=$PWD/native-trace" \
  ARCHS="arm64 x86_64" ONLY_ACTIVE_ARCH=NO \
  MACOSX_DEPLOYMENT_TARGET=10.13 CODE_SIGNING_ALLOWED=NO build
```

`LD_GENERATE_MAP_FILE=YES` and
`LD_MAP_FILE_PATH=$(NATIVE_TRACE_DIRECTORY)/$(PRODUCT_NAME)-$(CURRENT_ARCH).map`
produce **separate** `cURL-arm64.map` and `cURL-x86_64.map` files, not a
universal map or a last-writer-wins shared path. Do not select `Deployment`,
whose project script signs/notarizes. The diagnostic xcconfig does not disable
signing itself: the unsigned invocation must retain `CODE_SIGNING_ALLOWED=NO`.

On Windows (PowerShell), use the optional late MSBuild import:

```powershell
msbuild cURL.vcxproj /t:Rebuild /p:Configuration=Release /p:Platform=x64 `
  /p:PlatformToolset=v143 /p:WindowsTargetPlatformVersion=10.0 `
  "/p:ForceImportAfterCppTargets=$PWD\sbom-tools\build\sbom\diagnostics.props" `
  "/p:NativeTraceDirectory=$PWD\native-trace" /m:1 /nologo /v:normal `
  /fl "/flp:logfile=$PWD\native-trace\msbuild.log;verbosity=normal;encoding=UTF-8"
if ($LASTEXITCODE) { exit $LASTEXITCODE }
```

Create `native-trace` before opening the file logger. The import creates the
map directory before linking and enables
`/MAP` (`cURL-x64.map`) and `/VERBOSE:LIB`; it does not change library choices,
COMDAT/LTO optimization settings, or CRT settings.

Parser API (Python 3.10+, no extra dependencies):

```python
import linker

trace = linker.collect(root, "windows-x86_64",
                       {"map": "native-trace/cURL-x64.map",
                        "verbose": "native-trace/msbuild.log"}, candidates)
```

For production ingestion use `generate.py inputs`, which normalizes per-target
traces, matches resolved repository paths and hashes to the manifest/source
records, and binds everything to the binary:

```sh
python build/sbom/generate.py inputs --target macos-universal \
  --binary test/Plugins/cURL.bundle/Contents/MacOS/cURL \
  --manifest build/sbom/native-archives.json \
  --brotli-provenance brotli-provenance.json \
  --openssl-provenance openssl-provenance.json \
  --link-map macos-arm64=native-trace/cURL-arm64.map \
  --link-map macos-x86_64=native-trace/cURL-x86_64.map \
  --output sbom-macos.json
```

Windows uses `--target windows-x86_64`,
`--link-map windows-x86_64=native-trace/cURL-x64.map` and
`--link-log native-trace/msbuild.log`, with the Windows binary path.

`root` is the actual link working directory. `candidates` is the pre-link
declaration list, each entry with `path` and optional `sha256` (compatible with
`declaredInputs`). Relative paths resolve only against `root`; there is no
recursive search or basename substitution. Hash disagreement at the same
resolved selected path fails. Existing selected archives are hashed; missing,
foreign-host, system and external selections remain explicit records.
Raw diagnostic absolute paths and SHA-256 values are retained. The integrating
collector must bind the enclosing record to the final packaged binary hash.
Archive hashes describe files at collection time, so collect before overwriting
inputs and keep pre-link hashes for validation.
Each trace exposes `archives` (also available as compatibility alias
`selectedArchives`). An archive includes `selectedMembers` (member names),
`liveSymbols` and `deadSymbols` (limited observation lists), and detailed
`members` records. Only a selected repo-local archive whose resolved path and
hash match a supplied candidate receives `candidatePath`; missing candidate
hashes do not establish this binding. `candidatePath` can support identity
correlation even when `liveSymbols` is empty, as demonstrated by the real
force-loaded/dead-stripped and LTO map fixtures for both architectures.

Apple object tables report member selection, not live code. Only symbol-table
rows are recorded as limited live observations; dead-stripped rows are separate.
MSVC `/VERBOSE:LIB` supplies selected paths; `Searching`/`Found` alone do not
establish member loading. Map `LIB:obj` labels are correlated only when a unique
selected archive/member exists; duplicate library basenames remain ambiguous.
COMDAT folding, LTO synthesis and incomplete map visibility preclude claiming
that a loaded member contributes live code, or that unobserved code is absent.
