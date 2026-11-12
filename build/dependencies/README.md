# Native source-provenance migration

This is the authoritative migration checklist. Production linking, signing,
release assets and the historical identity rules are unchanged. The isolated
proxy candidate is **not approved for production**.

## Frozen baseline

`baseline-v4.9.10.json` is derived from the eight published
[v4.9.10 assets](https://github.com/miyako/4d-plugin-curl-v3/releases/tag/v4.9.10)
and [build 43220854896](https://github.com/miyako/4d-plugin-curl-v3/actions/runs/43220854896),
commit `9d82748eeeaa59aaa84a0c1e188cd1cb33bbb618`. The freezer verifies every
asset's SHA-256 against GitHub release metadata, inspects the ZIP and DMG
independently using the existing nonexecuting container reader, checks packaged
versions/binaries/slices, and requires identical saved target evidence. Asset
digest consistency is not itself a cryptographic provenance verification.

Download all eight assets into durable storage, then save release metadata,
run metadata and the actual build log:

```sh
gh release download v4.9.10 --dir "$EVIDENCE"
gh release view v4.9.10 --json assets,url,body > "$EVIDENCE/release.json"
gh run view 43220854896 --json headSha,jobs,url > "$EVIDENCE/run.json"
gh run view 43220854896 --log > "$EVIDENCE/build.log"
python3 build/dependencies/freeze_baseline.py \
  --release-directory "$EVIDENCE" --output build/dependencies/baseline-v4.9.10.json
```

Keep the original containers, inventories, sidecars and logs outside disposable
worktrees. The small checked-in summary is not a replacement for those records.
Historical prebuilt versions/configuration must not be inferred from this
checkout, headers, directory strings, or the old vcpkg helper script.

| Target | Selected / named / versioned archives | Source-built selected archives |
|---|---|---|
| macOS arm64 | 12 / 12 / 10 | 4 (OpenSSL and Brotli) |
| macOS x86_64 | 12 / 12 / 10 | 4 (OpenSSL and Brotli) |
| Windows x64 | 11 / 11 / 9 | 4 (OpenSSL and Brotli) |

The remaining **23 target/archive bindings lack source-build provenance**.
The summary separates unused repository candidates from non-repository linker
selections. `zs.lib` is not selected; Windows uses `zlib.lib` 1.3.1. Additional
vendor files do not expand migration scope without actual selection evidence.
The recorded macOS compiler command requests 10.13 (arm64 has the platform's
11.0 minimum); Windows uses `/MT`. Library search order and local project
settings are not changed. Runtime curl feature/protocol recovery is underway;
the original prebuilt configure arguments remain an explicit baseline gap.

## Checklist and gates

- [x] Preserve and independently inspect published containers and archive selections.
- [ ] Recover curl feature/protocol baseline and original configuration where possible.
- [ ] Resolve libproxy/libmodman replacement and static-distribution obligations.
- [x] Build/test the proxy candidate against exact baseline archives on all three targets.
- [x] Rebuild delivered library sources with a user modification and relink a
  standalone consumer on all three targets; independently inspect persisted proofs.
- [ ] Adopt only after an explicit replacement decision and plugin compatibility checks.
- [ ] Source-build selected prerequisites: zlib (1.3.2 macOS / 1.3.1 Windows),
  libiconv (1.16 / 1.18), nghttp2 1.70.0, macOS nghttp3 1.15.0, libssh2.
- [ ] Preserve the libssh2 `1.11.1_DEV` observation; establish an actual source
  identity, not a vulnerability/development conclusion from that suffix.
- [ ] Source-build curl 8.21.0 against verified prerequisites without losing features.
- [ ] Consolidate source records with existing OpenSSL/Brotli ingestion and check
  actual ftpparse/SDK compile inputs; do not introduce a second release SBOM model.
- [ ] Enforce source/patch/toolchain/configuration/output/selection/binary bindings
  for migrated libraries, including original records on any cache reuse.
- [ ] Run protocol/proxy/TLS/SSH/compression/conversion and deployment/CRT checks.
- [ ] Independently inspect persisted unsigned cross-platform ZIP and DMG outputs.
- [ ] Require zero opaque selected third-party archives, with explicit exclusions.

Never delete old archives/evidence before verified replacement. Historical
read-only analysis must remain supported. A release/sign/tag/merge requires
separate authorization; candidate CI has read-only repository permissions.

## Independent source prerequisites and curl observations

`native-sources.json` pins zlib 1.3.2 for both macOS architectures and 1.3.1
for Windows, preserving the selected versions. These are version-matched new
builds, not claims about the old archives' exact source commits. The Zlib
license assertion applies to the compiled core files, not unused `contrib`
material in the complete source tar.

```sh
python3 build/dependencies/build_native.py build --library zlib \
  --target macos-arm64 --source /clean/pinned/zlib --output /fresh/zlib-evidence
python3 build/dependencies/build_native.py inspect /downloaded/zlib-evidence
```

Use the target's immutable commit from the lock file and a clean source checkout.
The source kit retains canonical upstream bytes independently of checkout EOL
settings. For 1.3.1, the upstream configure-time `zconf.h` to
`zconf.h.included` rename must preserve exact bytes; all other source mutations
fail. The installed archive must equal the actual static compiler/archive
output. The wrapper copies that already indexed archive without CMake's
additional macOS install-time `ranlib` rewrite. Original compiler, archiver,
indexer, linker, build-system identities, generated headers, source allowlist,
commands, maps, probe executables and original test results are recorded.
Independent inspection rechecks the exact archive selection from each map and,
on Windows, its corresponding `/VERBOSE:LIB` output.

Five tests exchange raw-deflate, zlib and gzip streams in both directions
between the candidate and the exact selected old archive, reject truncated
streams and require full numeric equality of `zlibCompileFlags()` and version.
Both local macOS targets pass. This does not recover every old compiler option
or prove older operating-system compatibility. In particular, the linker
reports old macOS zlib objects built for macOS 26.0 despite the product's
recorded 10.13 compiler request; that warning is preserved, not reinterpreted
as evidence that the old objects support 10.13.

The manual-only `native-dependencies.yml` workflow builds/tests all three zlib
targets and separately observes exact baseline curl archives. It never writes
the production library directories. Its OpenSSL/Brotli providers reuse the
existing pinned build/evidence mechanisms; they are rebuilt matching-source
providers, not the historical release's archive bytes.
Before the new workflow exists on the default branch, dispatch the registered
`native-trace.yml` at this branch with `native-prerequisites-only=true`; its
isolated reusable-workflow route skips proxy, plugin and packaging jobs.

```sh
python3 build/dependencies/observe_curl.py observe \
  --target macos-arm64 --openssl-install /matching/openssl/install \
  --brotli-vendor /matching/brotli/vendor --output /fresh/curl-observation
python3 build/dependencies/observe_curl.py inspect /downloaded/curl-observation
```

The standalone public-API probe initializes libcurl only, never the plugin or
4D, and makes no transfers. It binds exact frozen curl/non-provider archives,
original provider records and delivered provider archives, actual interface
headers, probe/recipe bytes, commands, executable, map and runtime JSON.
The local arm64 observation reports curl 8.21.0, 14 feature names and 21
protocols: HTTP2, AppleSecTrust, OpenSSL, Brotli, zlib, threaded asynchronous DNS,
TLS-SRP and Unix sockets are among the enabled features. HTTP3, QUIC and zstd
are not advertised; selecting an nghttp3 archive is not proof of enabled HTTP3.
The original configure command is still unknown. Other targets require their
own persisted observations, not extrapolation from arm64.

## Host-verification prerequisites

Host verification is feasible but has not been performed. A local macOS 26.7
arm64 machine has an installed universal 4D 21.2 (build 21.100653), including
`com.apple.security.cs.disable-library-validation = true`. Rosetta execution
has been demonstrated by the standalone x86_64 tests. Neither fact proves
that a modified plugin loads, passes Gatekeeper or supports older hosts.
Windows 4D availability is not established; CI records only a bounded check
of default installation paths without launching a host.

Once the complete relink kit and modified plugin exist, the host operator needs:

1. A licensed compatible 4D host for each platform, an explicit macOS architecture
   choice, and a fresh isolated copy of `test/Project/test.4DProject`. Never use
   an existing user's project/data or modify the installed application.
2. Exactly one tested cross-platform `.bundle` in `Plugins`, **beside** the
   copied `Project` directory, as specified by the
   [4D plugin installation instructions](https://developer.4d.com/docs/Concepts/plug-ins).
   Quit only the isolated test instance before changing its plugin; retain
   separate baseline, unmodified-candidate and user-relinked test directories.
3. A user-controlled signing/trust path. On a copied macOS candidate,
   `codesign --force --sign - /isolated/Plugins/cURL.bundle` can supply local
   ad-hoc signing without maintainer credentials. Capture verification output
   and binary hashes before/after this byte-changing step. This is not
   notarization or a guarantee of acceptance; preserve any exact trust error
   and use explicit OS/user approval rather than disabling system policy or
   blanket-removing quarantine. Windows remains unsigned.
4. An operator-run launch for each architecture/platform, with isolated data
   and captured host/plugin-load errors. The supported
   [4D CLI](https://developer.4d.com/docs/Admin/cli) accepts an explicit project
   and interpreted opening mode; do not silently reuse a shared running host.
   Inspect `cURL_VersionInfo` in the debugger and save its JSON alongside host,
   architecture and final plugin hashes. The existing `TEST_version_info`
   convenience method overwrites the clipboard; use it only deliberately.
5. Evidence that an actual modification of the delivered LGPL library survives
   full-plugin relinking and is observable through that loaded plugin, followed
   by the affected proxy/protocol tests. The standalone new-function proof is
   not a substitute. Retain the kit, modification, build and installation logs.

No host action is needed while independent source prerequisites are being
built. Request the concrete operator-run check when complete materials exist;
lack of a hosted CI installation must neither waive this gate nor stop the
independent migration. Analysis tools must not launch or initialize 4D.

## Measured results and scoped candidate decision

Checkpoint `d93ab29` passed all five candidate/baseline test executables and
all five delivered-library relink test executables on macOS arm64, macOS x86_64
and Windows x64 in [run 43244909872](https://github.com/miyako/4d-plugin-curl-v3/actions/runs/43244909872).
All six downloaded candidate/relink artifacts were independently inspected,
without running downloaded binaries. This verifies the isolated libraries and
their source kit, not production adoption, a complete plugin kit or host loading.

[First isolated run 43235756612](https://github.com/miyako/4d-plugin-curl-v3/actions/runs/43235756612)
built all three native targets. Both macOS jobs passed all four test executables;
their downloaded source/recipe/archive records were independently inspected.
Windows compilation succeeded, but two tests failed. These are retained
**rejections**, not evidence of full compatibility:

- The old Windows archive ignores a multi-entry `ProxyOverride` list, while the
  candidate applies it. Upstream change
  [`75e349c6734573fb60f1e0a3c4af3e6e43a289cf`](https://github.com/libproxy/libproxy/commit/75e349c6734573fb60f1e0a3c4af3e6e43a289cf)
  explains the candidate's behavior: split semicolons and return the full list,
  rather than accepting only the exact string `<local>`. This supports an
  intentional bug-fix decision, **not** assigning the old archive a revision.
- The pinned upstream Windows URL tests expect conversion of drive-letter and
  UNC `file:` URLs, but this revision's `url::get_path()` returns the unchanged
  parsed path. This is a source/test mismatch, not a compiler failure.
  Libproxy's file-path handling is used for fetching local PAC files, not the
  plugin's normal libcurl transfer/file-path options. With no built-in Windows
  PAC runner and external modules isolated, the tested PAC lookup falls back
  to direct. This does not establish safety with external PAC modules or
  eliminate the upstream defect.

The product reaches libproxy through `AUTOPROXY` in
`4DPlugin-cURL.cpp:1154-1184`; ordinary transfer paths/options go to libcurl.
The wrapper skips `direct://` entries and an explicit `PROXY` option is applied
after automatic settings. Thus library comparisons are not a claim that the
4D wrapper retries ordered PAC entries or forcibly disables environment proxy
settings. Those product behaviors are not changed by this migration.

The user selected continued candidate validation with the deliberate bypass
fix, a narrowly reviewed Windows file-URL correction, and completion of
LGPL/relink materials before production adoption. This is not adoption or
release authorization. The current fixture separately asserts the observed
legacy multi-entry bypass failure and the candidate's corrected behavior;
`acceptedCandidateChanges` records that scoped decision. All other comparison
expectations remain intact.

`patches/proxy-windows-file-url.patch` converts Windows drive-letter and UNC
paths for `file:`/`pac+file:` and uses the converted path for actual PAC reads.
The source delta is allowlisted by exact before/after hashes. A separate
candidate-source test covers drive letters, UNC, localhost, both file schemes,
actual local PAC contents, unchanged root-relative/HTTP paths and unchanged macOS paths.
This does not add a Windows PAC interpreter, percent decoding or remote-PAC
changes.
The [bounded Windows run 43242932768](https://github.com/miyako/4d-plugin-curl-v3/actions/runs/43242932768)
passed the upstream URL parsing/encoding and public-API comparisons, but isolated
a local PAC read defect: the library returned 168 bytes with a trailing CR
instead of the stream's 164 translated bytes. Windows `_read` can translate
CRLF in place and leave residual bytes beyond its returned count; pre-zeroing
the allocation does not terminate the translated result. The patch now
terminates at the actual read count and rejects failed reads. Both LF and CRLF
fixtures are checked through both file schemes on every target. No remote PAC
fetching or text-mode policy is changed. These private-class source tests do
not identify or assume the C++ layout of the opaque old archives.
The scoped `.gitattributes` keeps reviewed patch bytes LF on Windows too;
checkout line-ending conversion must not change the locked patch digest.

## Isolated proxy candidate

`proxy-source.json` pins upstream tag 0.4.17 to commit
`e78a5ccfe0a2340f2c73e419767f8492ffc2787a`. It is a conservative **candidate**,
not recovered historical provenance: its public `proxy.h` exactly matches the
vendored header (SHA-256
`9d2fa8033a38c164d137b97ad93278f7ee70075934dd4f30a31743120fdfd810`),
and its module families match the old selected members. The 0.4.17 directory
string supports investigating this candidate, not identifying the old archives.
The 0.5 rewrite is deliberately not substituted. `libmodman` is bundled source
at this commit and has no invented independent version.

The recipe builds only the observed modules: macOS SystemConfiguration,
JavaScriptCore PAC, domain/hostname/IP bypass and DNS-alias WPAD; Windows registry,
domain/hostname/IP bypass and DNS-alias WPAD. No environment-variable backend,
GLib or Windows PAC engine is added. Observed default module-directory strings
are retained. Loading externally installed modules is still possible and those
modules are not covered by this candidate's provenance.

```sh
python3 build/dependencies/build_proxy.py build --source /path/to/clean/pinned/libproxy \
  --output /durable/fresh/proxy-candidate --target macos-arm64
python3 build/dependencies/build_proxy.py verify --source /path/to/clean/pinned/libproxy \
  --output /durable/fresh/proxy-candidate --target macos-arm64
```

Use the corresponding native target for macOS x86_64 or Windows x64 (MSVC
developer environment, CMake and Ninja). The existing **Unsigned native linker
trace** workflow accepts `proxy-candidate-only=true` to run only this isolated
three-target comparison. It does not replace vendor archives or build/sign the
plugin. The same public-API fixture links separately to the exact old archives
and to newly built candidate archives. Tests inject synthetic macOS preferences
or process-local Windows registry redirection, not host proxy configuration.
Five native test executables cover direct/manual HTTP/HTTPS/SOCKS selection, host/local bypass, invalid
URLs, local macOS PAC ordering and Windows' direct fallback without a built-in PAC runner;
upstream URL parsing/encoding tests also run. WPAD discovery, real proxy
authentication, remote PAC fetching and the full plugin remain separate gates.

The builder reuses existing SBOM provenance hash/path helpers. It records
complete clean-source hashes before/after compilation, immutable commit,
licenses, exact reviewed patches, explicit module list, actual compile
commands, toolchain executable hashes, CMake compiler metadata, logs, original
baseline hashes, installed archives and source/recipe tarballs. Checkout bytes
are recorded separately from canonical `git archive` source and the actual
patched compile inputs; line-ending conversions do not erase either record.
Archive creation and patch application explicitly disable Git's working-tree
line-ending conversion without changing the source checkout or Git settings.
Only the exact reviewed source delta is accepted, and additional staged headers
or other files fail verification. Existing output
directories are rejected, not assigned fresh provenance. Verification checks
the original record and bytes without rebuilding. These **candidate-only**
records are not release SBOM identities or plugin selection evidence.
`inspect_proxy.py OUTPUT` independently checks downloaded records, actual
archive-member CPUs, source/recipe tar contents, installed license/header
bindings and original build logs without relying on the original runner paths
or executing any downloaded binary.
Failed native tests retain a source/archive build record with
`validationStatus: failed`; the build and default verifier still fail.
`inspect_proxy.py --allow-failed-tests OUTPUT` supports explicit read-only
inspection of rejected candidates and reports failed tests, without waiving
the compatibility/adoption gate.

## Delivered-library user-relink proof

The recipe tar preserves repository-relative paths and includes the required
SBOM hash/object helpers, root recipe license, patch, test sources and these
instructions. The source tar contains the actual patched compile inputs,
including all original notices and license text; the base tar retains the
canonical immutable upstream source.
The patched file carries a dated change notice; the relink driver also dates
its demonstration change in the modified source and original proof record.

```sh
python3 build/dependencies/relink_candidate.py \
  --candidate /path/to/downloaded/candidate --output /fresh/user-relink
python3 build/dependencies/relink_candidate.py --inspect-only \
  --candidate /path/to/downloaded/candidate --output /path/to/downloaded/relink
```

The first command verifies the delivered candidate, extracts its delivered
sources and build recipe into a fresh directory, adds a benign new C function
to the library source, rebuilds both static libraries and relinks a standalone
test against that modified library. The probe must return the new value and
the normal candidate URL/proxy/PAC tests must still pass. The modified archive,
resulting test executable, source delta and original logs are hash-bound.
The second command independently inspects persisted bytes without running them.
CI uploads separate source-candidate and user-relink proof artifacts.
Uploads preserve hidden source/recipe files from the isolated output directories;
checkout `.git` metadata is not included.

This verifies **library-source** rebuild/relink usability only. It does not
supply or verify a complete 4D plugin relink kit. That kit still needs every
selected library's corresponding source/compatible objects, product/SDK build
materials and resources, followed by both plugin architectures/platform builds.
The hosted CI runners have no configured 4D host/install test. Local host
availability and the concrete procedure above do not verify modified-plugin
loading, trust/local-signing or user installation. These remain
explicit production-adoption gates, not obligations satisfied by this document
or by the standalone probe.

## Static-distribution decision (not a legal-compliance claim)

Both libraries' compiled source notices say LGPL 2.1 or later; the pinned
`COPYING` contains LGPL 2.1. Keep that actual text and all applicable notices,
including the Red Hat attribution in `url.cpp`, with corresponding source.
The macOS-compiled `modules/pacutils.h` embeds Mozilla/Netscape PAC JavaScript
under its original NPL/GPL/LGPL alternative notice; its stated LGPL 2.1-or-later
option is explicitly offered by the original notice and is recorded for the
candidate. Preserve
that complete original notice rather than erasing the alternative grants.
Identifying these notices alone does not establish compliance for a distributed
static plugin. The plugin's own MIT license does not relicense these libraries.

Before any adoption/release, review an LGPL 2.1 section 6(a) delivery approach:

1. Ship the complete corresponding pinned library source, all local patches,
   license/notices, dated modified-file notices and exact build/install recipes
   with each binary release,
   not a floating upstream link or an unsupported source offer.
2. Provide the complete machine-readable material needed to relink the plugin
   with modified libraries: product and SDK sources or usable objects,
   compatible remaining archives and their licenses, resources/export files,
   compiler/linker flags, platform/toolchain requirements and reproducible
   instructions. Avoid LTO-only objects that cannot be relinked with the
   documented toolchain. Verify this kit by actually rebuilding/relinking both
   macOS slices and Windows x64 independently.
3. Give prominent LGPL library-use notices and terms permitting modification
   for the user's own use and reverse engineering for debugging such changes.
   Keep third-party terms distinct from MIT product attribution; review any
   host/SDK and other static-library restrictions for compatibility.
4. Demonstrate a usable user-relinked bundle/install path without the
   maintainer's signing credentials; document local signing/trust requirements.
   Do not assume the 4D host accepts the resulting modified plugin.

Candidate artifacts include source and recipe material to support review, but
are **not a complete plugin relink kit**. Upstream defects, configuration
differences, feature coverage and any remaining redistribution/licensing
questions must be resolved explicitly before a single actionable adoption
decision is sought. Historical archive versions/licenses stay unknown.
