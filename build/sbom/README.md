# Release SBOM proof of concept

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
claim. There are two separate evidence classes:

1. **Analyzed binary observations:** narrow identifying-string rules for curl,
   OpenSSL, libssh2 and zlib, applied separately to each architecture's actual
   bytes. Versions retain suffixes such as `1.11.1_DEV`. Each observation
   records the matched text and offset relative to the analyzed slice/PE.
   Conflicting versions, absent curl identification, unsupported binary
   layouts, duplicate ZIP members and version mismatches fail explicitly.
   A marker establishes an observation, not runtime verification, feature
   availability or a complete dependency graph.
2. **Build-derived candidate inputs:** future release builds capture declared
   Xcode framework-phase archives and MSBuild `Release|x64` libraries, the
   available repository-relative archive hashes, unresolved declarations,
   source checkout commit and configuration-file hashes. These records are
   bound to the exact packaged binary hash. The existing pinned Brotli build
   additionally records the version from its source `c/common/version.h`,
   source commit and hashes of its three newly built archives; the consuming
   jobs verify those hashes against the declared inputs. This is explicitly
   build-derived, **not** Brotli version detection in the distributed binary.
   Build records are embedded in both formats and the inventory, not promoted
   into asserted incorporated-library components.

The checked-in linker declarations still mention libraries beyond the six
dependencies listed in `build/build-libcurl-macos.sh`, including QUIC/HTTP3,
IDN and legacy proxy/LDAP inputs. That script is not treated as an authoritative
manifest of the released binary. The collector does not pretend that every
declared archive contributes code, resolve absolute developer-machine search
paths, or silently substitute another file for an unresolved declaration.
MSVC system `.lib` declarations can therefore appear unresolved.

nghttp2 and Brotli, among others, can lack sufficiently identifying version
strings even when statically incorporated. Bare version numbers, header
versions and printf templates are not enough to assign a binary component
version. Static linking and dead stripping can also hide libraries entirely.
Dependency licenses, PURLs and suppliers are not inferred. SPDX uses
`NOASSERTION`; CycloneDX omits those fields and declares an `incomplete`
composition. No complete dependency edges are asserted. SPDX `CONTAINS`
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

Normal builds, signing, notarization and packaging remain unchanged.
Brotli's existing workflow artifact gains a small provenance JSON file.
Windows and macOS record their declarations after linking (macOS after signing).
The packaging job requires both platform records and verifies their binary
hashes against **each** container before publishing sidecars through the existing
release upload step. Generation or validation failures stop publication instead
of uploading misleading documents. No new signing secrets are needed.

Release jobs check out the SBOM scripts separately from the workflow revision,
so manual builds of older tags do not require scripts in that old source tree.
This PoC does not backfill or overwrite historical release assets. The
SBOM-only workflow is the safe way to analyze an already-published release.
No full signed release was triggered to demonstrate this change.
