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

Those **23 historical target/archive bindings lack source-build provenance**;
the isolated source candidates below do not retroactively identify their origin.
The summary separates unused repository candidates from non-repository linker
selections. `zs.lib` is not selected; Windows uses `zlib.lib` 1.3.1. Additional
vendor files do not expand migration scope without actual selection evidence.
The recorded macOS compiler command requests 10.13 (arm64 has the platform's
11.0 minimum); Windows uses `/MT`. Library search order and local project
settings are not changed. Runtime curl feature/protocol recovery is complete;
the original prebuilt configure arguments remain an explicit baseline gap.

## Checklist and gates

- [x] Preserve and independently inspect published containers and archive selections.
- [x] Recover observable curl features/protocols on all targets; retain unknown
  historical configure arguments as an explicit residual.
- [ ] Resolve libproxy/libmodman replacement and static-distribution obligations.
- [x] Build/test the proxy candidate against exact baseline archives on all three targets.
- [x] Rebuild delivered library sources with a user modification and relink a
  standalone consumer on all three targets; independently inspect persisted proofs.
- [ ] Adopt only after an explicit replacement decision and plugin compatibility checks.
- [x] Isolated source-build selected prerequisites: zlib (1.3.2 macOS / 1.3.1 Windows),
  libiconv (1.16 / 1.18), nghttp2 1.70.0, macOS nghttp3 1.15.0, libssh2.
- [x] Preserve the libssh2 `1.11.1_DEV` observation; establish the candidate's actual
  source identity, not the historical archive's origin or a vulnerability/development
  conclusion from that suffix.
- [x] Isolated source-build curl 8.21.0 against verified prerequisites without losing features.
- [x] Consolidate source records with existing OpenSSL/Brotli ingestion and check
  actual ftpparse/SDK compile inputs; do not introduce a second release SBOM model.
- [ ] Strengthen the twelve original OpenSSL/Brotli bindings' compiler/object/build materials.
- [x] Enforce source/patch/toolchain/configuration/output/selection/binary bindings
  for the twenty-three migrated candidate inputs in safe isolated CI, retaining original records.
- [x] Verify actual all-target source-candidate plugin selections and full
  original-object modified-proxy relinks on Mac and Windows.
- [x] Relocate Mac source/object materials and verify modified delivered proxy
  and GNU iconv sources in both full-plugin slices.
- [x] Verify portable Windows source/object and GNU modification/relink execution.
- [ ] Run protocol/proxy/TLS/SSH/compression/conversion and deployment/CRT checks.
- [x] Independently inspect persisted unsigned cross-platform ZIP and DMG outputs.
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
The source producers also require exact multiset equality between compiled
object payload hashes and archive member payload hashes. Windows CMake's
`vs_link_exe` suppresses successful linker diagnostics unless `VERBOSE` is
present in its environment; the recipe sets it for the bounded build command.
Missing selection diagnostics remain a rejection, not a basename fallback.

Five tests exchange raw-deflate, zlib and gzip streams in both directions
between the candidate and the exact selected old archive, reject truncated
streams and require full numeric equality of `zlibCompileFlags()` and version.
All three native targets pass in
[run 43255384031](https://github.com/miyako/4d-plugin-curl-v3/actions/runs/43255384031)
at `d85d6ba`; their downloaded original records were independently inspected.
This does not recover every old compiler option
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
For a GNU-only recheck, also set `native-prerequisite-scope=iconv`; scoped
concurrency keeps that run from canceling an independent in-flight provider/SSH
matrix. The default remains the full native prerequisite matrix.

```sh
python3 build/dependencies/observe_curl.py observe \
  --target macos-arm64 --openssl-install /matching/openssl/install \
  --brotli-vendor /matching/brotli/vendor --output /fresh/curl-observation
python3 build/dependencies/observe_curl.py inspect /downloaded/curl-observation
```

The standalone public-API probe initializes libcurl and a standalone libssh2
session, never the plugin or 4D, and makes no transfers. It binds exact frozen curl/non-provider archives,
original provider records and delivered provider archives, actual interface
headers, probe/recipe bytes, commands, executable, map and runtime JSON.
Both independently inspected macOS observations from
[run 43251815097](https://github.com/miyako/4d-plugin-curl-v3/actions/runs/43251815097)
report curl 8.21.0, identical 14 feature names and 21
protocols: HTTP2, AppleSecTrust, OpenSSL, Brotli, zlib, threaded asynchronous DNS,
TLS-SRP and Unix sockets are among the enabled features. HTTP3, QUIC and zstd
are not advertised; selecting an nghttp3 archive is not proof of enabled HTTP3.
The original configure command is still unknown. Other targets require their
own persisted observations, not extrapolation from arm64.
The extended probe also records the exact ordered libssh2 algorithm lists in
both directions, including compression. The local arm64 baseline advertises
only `none` for SSH compression; this informs the version-matched source
recipe rather than enabling compression merely because zlib is selected.
These lists describe supported API algorithms, not successful negotiation,
authentication or interoperability with a live SSH server.
The Windows raw observation from
[run 43258085914](https://github.com/miyako/4d-plugin-curl-v3/actions/runs/43258085914)
reports 18 features and the same 21 protocols, with
`OpenSSL/3.5.8 (Schannel)`, MultiSSL, Kerberos, SPNEGO, SSPI and Unicode.
Its old single-backend validation assumption rejected that legitimate banner;
the target-specific check now preserves the dual-backend requirement and the
probe enumerates available TLS backends before initialization without selecting
one. This measurement is not a successful TLS handshake or original configure
argument recovery. The corrected Windows record from
[run 43262905033](https://github.com/miyako/4d-plugin-curl-v3/actions/runs/43262905033)
was downloaded and independently inspected: its cold enumeration reports
`openssl`, then `schannel`, with all 18 features and 21 protocols preserved.

`build_http.py` adds version-matched nghttp2 1.70.0
(`85e300c79fb6dbcfa9c1013215c8710c1c2cd3d2`) and macOS nghttp3 1.15.0
(`d326f4c1eb3f6a780d77793b30e16756c498f913`) source prerequisites under the
same isolated native-record contract. It preserves MIT texts, exact source
and compiled-object/archive bindings, recipes, toolchains and upstream test
logs. Parent-pinned munit sources are test-only; nghttp3's required sfparse
commit `ff7f230e7df2844afef7dc49631cda03a30455f3` is separately captured as
compiled parser source. Its nested, unused munit pointer and nghttp2's unused
application submodules do not become incorporated library dependencies.

All three nghttp2 targets pass 194 upstream main cases; both macOS nghttp3
targets pass 56 cases without skips in
[run 43255384031](https://github.com/miyako/4d-plugin-curl-v3/actions/runs/43255384031).
All five downloaded source/object/archive records were independently inspected.
These are **source self-tests**, not old/new
interoperability or full-plugin compatibility proof. Allocator fault-injection
tests are not enabled. The native matrix also builds nghttp2 on Windows;
nghttp3 is deliberately absent from Windows because it is not selected there.

```sh
python3 build/dependencies/build_http.py build --library nghttp2 \
  --target macos-arm64 --source /clean/pinned/nghttp2 --output /fresh/http-evidence
python3 build/dependencies/build_http.py inspect /downloaded/http-evidence
```

Initialize only the parent-pinned `tests/munit` submodule for nghttp2;
nghttp3 additionally requires `lib/sfparse`. Do not use floating submodule
branches. Original acquisition tars, actual checkout bytes, canonical staged
compile inputs and unused gitlink pointers remain distinct evidence.
Old/new HTTP interoperability, libiconv, libssh2, curl rebuild,
complete plugin materials and host validation are still open gates.

### Version-matched SSH and pending release-source acquisitions

`build_ssh.py` builds libssh2 tag `libssh2-1.11.1`, pinned commit
`a312b43325e3383c865a87bb1d26cb52e3292641`, against the verified matching-source
OpenSSL provider. The tag itself reports `1.11.1_DEV`; this matches the
observed banner but does not identify the historical archive's source commit.
Both isolated local macOS builds pass upstream `test_simple` and exactly preserve
all eight ordered supported-algorithm lists, including disabled SSH compression.
Native CI runs the same gate on each target, reusing its fresh baseline/provider
job rather than choosing an unobserved Windows configuration.
The downloaded Intel record from run 43262905033 independently passes its
26-object source/archive binding and algorithm checks. Windows reached and
passed `test_simple` but correctly stopped at the CRT gate: CMake's old policy
default generated `/MD` despite the requested runtime setting. The recipe now
explicitly sets `CMAKE_POLICY_DEFAULT_CMP0091=NEW` before configuration; actual
compiler commands must still prove `/MT`, without dynamic/debug CRT flags.
The next run exposed a second issue: CMake's Windows OpenSSL finder selected
its legacy `LIB_EAY_RELEASE` system installation despite explicit generic
provider paths. The recipe confines those imported configurations to the
delivered provider and requires actual `/VERBOSE:LIB`/map selections from the
upstream unit executable as well as the separate API probe. Both corrections
required fresh native Windows results, not relabeling rejected outputs.
Run 43269868412 passed the unit/API checks with the delivered provider but
stopped at record verification because Ninja's `src\libssh2.lib` diagnostic
was relative. The resolver now requires its explicit original build directory;
it never substitutes a matching basename or guesses a search directory.
The fresh Windows SSH output from
[run 43272822829](https://github.com/miyako/4d-plugin-curl-v3/actions/runs/43272822829)
was downloaded and independently inspected successfully: 26 source-bound
archive objects, `/MT`, the delivered OpenSSL provider selected by both
executables, upstream `test_simple`, and exact ordered algorithm equality.

The producer retains source kits, original provider records and installed headers,
generated configuration, compiler objects, archive-member payload bindings,
actual probe selections, binary/map hashes and original test outputs. It never
replaces the production libssh2. Docker/sshd tests are disabled and only the
standalone `test_simple` case is run; neither that case nor supported-algorithm
equality proves live SSH negotiation, authentication or SFTP interoperability.

```sh
python3 build/dependencies/build_ssh.py build \
  --source /clean/pinned/libssh2 --target macos-arm64 \
  --openssl-install /matching/openssl/install \
  --baseline /measured/curl-observation --output /fresh/ssh-evidence
python3 build/dependencies/build_ssh.py inspect /downloaded/ssh-evidence
```

### Isolated curl source reconstruction

`build_curl.py` consumes the SHA-pinned, signed-release curl 8.21.0 source
archive and independently validated original SSH, zlib, nghttp2 and curl-baseline
kits. It preserves those kits rather than assigning new provenance to reused
archives. Brotli public headers and LICENSE are separately staged from the
same immutable source commit as the original provider; that header-only
closure is not a new claim of complete Brotli build provenance.

The producer retains acquired sources, original recipes, generated configuration,
actual compiler/object/archive bindings, delivered interfaces, tool/SDK records,
exact selected provider archives and the standalone executable/map/runtime
outputs. Every measured field must match the target baseline, including feature
bits, ordered protocols, both Windows TLS backends and all SSH algorithm lists.
Only the descriptive host string may differ; both values are explicitly recorded.
Original configure arguments remain unknown: this is a matching reconstruction,
not retroactive provenance for the old archives.

Both native macOS outputs from
[run 43277451082](https://github.com/miyako/4d-plugin-curl-v3/actions/runs/43277451082)
were downloaded and independently inspected: each binds 192 objects and matches
the measured configuration. Windows built its archive but exposed the actual
`libcurl_object` CMake target rather than the direct `libcurl_static` compilation
target. Its preserved 192 compiler objects exactly match the archive payloads;
the selector now accepts that original object-library route without dropping
source, CRT or archive-binding checks. Its next link exposed nghttp2 DLL imports
despite the explicit static archive. The recipe now requests upstream's documented
`NGHTTP2_USE_STATIC_LIBS=ON` and verifies `NGHTTP2_STATICLIB` in actual Windows
compiler commands; it does not invent an import shim or disable HTTP2.
The rejected outputs remain preserved; no success record was written over them.

The corrected three-target run `43280340259` at `141de19` passed. All three
persisted kits were downloaded and independently inspected without executing
downloaded probes: each binds 192 actual compiler objects to archive members,
the original prerequisite records and exact selected provider bytes, and the
complete measured baseline configuration. Windows retains OpenSSL+Schannel,
SSPI/Unicode, static CRT and static nghttp2 rather than DLL imports. This closes
the isolated curl source/configuration gate, not network-transfer compatibility
or production adoption. The original curl and GNU kits also have separately
verified archive backups outside both worktree and session storage.

### Shared source inventory integration

`build/sbom/native_provenance.py` adapts inspected curl/zlib/nghttp2/nghttp3/libiconv/libssh2
kits into the existing `rebuiltArchiveEvidence` model, consumed by both SBOM
emitters. It rechecks original source/compiler/archive records, requires both
macOS architectures, binds every universal slice or Windows copy, and retains
original record/recipe/toolchain hashes. A signed release tarball remains an
exact-hash source archive; its related Git tag is not promoted to a source commit.
`generate.py inputs --native-source-kit PATH` repeats inspection at final input
collection. Only actual hash-matched linker selections receive package identity.
The actual curl translation units include ISC notices in `vssh/vssh.c` and
`curlx/inet_{ntop,pton}.c`; the aggregate license is `curl AND ISC`, not the root
COPYING identifier alone. Both formats retain this as a standard expression
and the source record retains the additional notice-file hashes.

The adapter's CLI creates a **new** isolated vendor-layout directory; it refuses
existing outputs. The curl source workflow stages curl/zlib/nghttp2 on both
platforms using this path and retains merge commands/tool identity. This is not a
full plugin or release package. GNU iconv's aggregate license expression retains
both LGPL-2.1-or-later core and LGPL-2.0-or-later localcharset/relocatable terms;
its original notices and static delivery/relink gate are not waived.
SSH retains its complete reviewed BSD, ISC-style and public-domain comment
notices as one extracted `LicenseRef` collection, not a blanket BSD-3-Clause or
MIT/CC0 relabeling. Proxy/modman adapters and the LGPL delivery gates remain open.
Historical input collection without the new option is unchanged.
Normalized sidecars alone do not satisfy relink/host gates.

The `inventory` dispatch scope can reuse original curl, GNU and nghttp3 outputs
without rebuilding or restamping them. Supply `native-provider-run` (original
HTTP prerequisites), `native-curl-provider-run`, and optionally
`native-iconv-provider-run`. Every original run must be explicitly dispatched
from this repository/branch, with every exact target producer successful on its
latest attempt. Incomplete job enumeration fails. Original records are then
inspected again; source jobs are skipped and only fresh isolated copies and
merge/evidence records are produced. No plugin, signing or release job runs.

Run `43286514052` at `2014282` passed this reuse path. Downloaded universal
macOS and Windows staged archives and normalized records were independently
compared with all original kits: 12 macOS plus five Windows source/archive
bindings matched, without running downloaded binaries. This is candidate
source/copy evidence, not final-plugin selections or production coverage.

### Proxy compiler-object closure

Fresh proxy records use schema 2 to bind each exact compiler source/working
directory and static-CRT setting to both archive payloads, retaining every
compiler object, original built archive, installed hash and install script.
Schema 1 remains inspectable as historical hash/architecture evidence; it does
not acquire the new compiler-payload claim retroactively. A shared read-only
object comparator is used by proxy and the other native producers.

The local arm64 schema-2 build and delivered-source modified-library standalone
relink passed. macOS CMake install ran `ranlib`, changing only one byte in the
first symbol-table timestamp field for each archive. The verifier permits only
that bounded macOS header-field delta, records it explicitly and preserves both
exact archive hashes; any code/member/index-payload difference fails. Windows
still requires byte-identical installation. Run `43290332315` at `69215c3`
passed all three fresh native builds/comparisons and delivered-source modified
standalone relinks. Downloaded originals were independently inspected:
libmodman has one compiler-bound object per target, and libproxy has eleven on
each Mac architecture and ten on Windows. The Windows installation is
byte-identical. Original schema-1 run `43245630276` was also re-inspected without
claiming compiler-object closure. Earlier rejected attempts are preserved;
their Windows failures were a path-separator test fixture and rejection of
CMake's valid `-MT` spelling, not dynamic-CRT builds or product behavior changes.

The shared native adapter also accepts these fresh schema-2 proxy kits. It
projects the two original archives separately, retaining the original record
hash, component-specific object proof, project patch/change decision and
toolchain evidence. `libproxy` has version `0.4.17`; bundled `libmodman` has no
independently established release version and does not inherit that version.
Its source identity is the pinned project's `libmodman` subdirectory. Schema-1
kits remain readable by the historical inspector but cannot enter this stronger
source inventory. Only actual hash-matched final selections can promote either
component, and the LGPL/full-plugin/host gates remain open.

For optional proxy aggregation, pass `native-proxy-provider-run` alongside the
other explicit original producer IDs in inventory-only mode. This requires all
three exact latest proxy producer jobs to succeed before acquiring their kits.
The inventory then re-inspects the original source/patch/compiler/object
materials and binds fresh isolated copies/universal slices; it does not rebuild,
restamp, replace production archives or waive adoption gates.

Run `43290901171` at `14e0ca5` passed this complete candidate aggregation.
The downloaded inventory was independently recomputed against every original
kit: sixteen architecture/archive bindings on macOS and seven on Windows,
covering all twenty-three previously opaque input positions with new isolated
source candidates. Twenty have independently supported versions; bundled
libmodman's three bindings remain deliberately unversioned, with pinned source
identity and LGPL text instead. These counts do not retroactively identify or
replace the twenty-three opaque production bindings.

The original native outputs, source inventory and historical/rejected proxy
evidence have verified independent backups outside both worktree and session
storage. Remaining migration work includes stronger consolidation of existing
OpenSSL/Brotli build materials, actual full-plugin source-candidate selection,
complete LGPL corresponding-source/user-relink delivery, operator-run 4D
installation/trust/behavior checks and representative cross-platform packaging.
No production archive, signing setting, tag or release was changed.

`native_provenance.py --project-source REPOSITORY --output NEW_DIRECTORY`
prepares the next isolated full-plugin experiment. It requires the complete
target's source-candidate stack and clean committed project source, clones that
commit into `NEW_DIRECTORY/project`, and stages only this separate checkout.
The normal source candidates and their public curl/iconv/proxy headers are
rechecked. OpenSSL and the two selected Brotli libraries are bound back to the
original preserved curl-provider records, with exact Windows copies or verified
Mac universal slices. Existing OpenSSL combination and shared SBOM ingestion are
reused; the original weaker provider evidence is not relabeled as compiler-object
closure. The staging record makes this residual explicit.

This mode does not compile/load a plugin, authorize adoption or provide a
self-contained LGPL delivery: its shared Git object store and original kits are
external dependencies. Full compilation/link selection, portable source/relink
materials, corresponding license obligations and actual host checks remain
separate gates. The caller's checkout and production archives are never staging
destinations.

The first local isolated universal Mac plugin built successfully at project
commit `edd7dcf`, using the actual Xcode target, Default configuration and
`CODE_SIGNING_ALLOWED=NO`; the Deployment signing/notarization branch was not
run and no application was loaded. Both real link maps were ingested and
independently checked against pre-link candidate hashes: twelve repository
archives per architecture have source-record bindings, eleven versioned.
The additional selected Clang runtime archive is a system/toolchain exclusion.
The binary SHA-256 is
`1078df8ac0bfb0e7c26e6a193f7e5b28b8c2e1f83f5904ca3cd7eadb15749b99`.
This includes the original weaker OpenSSL/Brotli records and is not modified-
library full-plugin relink or host/protocol verification.

Actual ingestion exposed libiconv's selection through linker flags rather than
the explicit Xcode frameworks phase. Only independently inspected native source
kits can cover such an undeclared candidate; final promotion still requires its
actual hash-matched linker selection. Arbitrary legacy provenance files do not
gain this exception, and no library search order or project declaration changed.

The manual `native-candidate-plugin-only=true` route takes an explicit
`native-candidate-inventory-run`. It rechecks that inventory producer and all
four original source producer sets, downloads their original kits and uses the
separate project staging mode above. Existing unsigned plugin/link-map and
ZIP/DMG/SBOM jobs are reused, with candidate-specific source-selection counts.
Pre-link archive hashes must remain unchanged across compilation. Legacy
read-only/default analysis keeps its original expected unknown versions.
This route does not run the Deployment signing branch, rebuild/restamp old
providers, adopt candidates, load 4D or publish anything. It is not the eventual
complete user-modified-library relink/host verification gate.

The local full Mac plugin was subsequently relinked from its unchanged original
objects using each architecture's reviewed user-modified proxy archive.
Both unchanged baseline link replays reproduced the original slice bytes;
both modified full-plugin slices retained the defined probe symbol and differed
from the originals. The merged modified binary SHA-256 is
`d5950062d39d79a25b70b6bca0023318dc1776697e3047cb4e9a13db641d1bcb`.
`relink_plugin_macos.py` captures the actual commands, object/library hashes and
original source-kit bindings; `--inspect-only` rechecks the persisted proof
without compiling or loading the plugin. This is a local object-relink
demonstration, not portable LGPL delivery or an actual 4D host check.

The first cross-platform source-plugin run, `43295977632` at `0e6a14f`,
exposed a concrete Windows toolchain incompatibility: the proxy producer used
MSVC 14.51, but the unchanged plugin's v143 link used 14.44. Its static STL could
not resolve `__std_find_first_not_of_trivial_pos_1` and
`__std_find_last_not_of_trivial_pos_1` from `proxy.cpp.obj`.
The isolated proxy producer now explicitly selects the v143 14.4 family,
and its delivered CMake recipe rejects newer MSVC STL inputs. The source-plugin
experiment uses the matching developer environment; default historical builds
and the product's toolset/CRT/search order are unchanged. Fresh source and
full-plugin CI are required before treating this correction as verified.
The original producer kits and failed native diagnostics remain preserved.

Fresh proxy run `43297884035` at `749a99d` passed all three native comparisons
and delivered-source modified-library standalone relinks. Downloaded originals
were independently re-inspected; Windows actually used MSVC 19.44.35229.0 from
toolset 14.44.35207, with static release CRT and exact compiler-object/archive
closure. Complete inventory run `43298364687` incorporates these original kits
without rebuilding/restamping the other providers.

The source-plugin-only Windows route also attempts the actual original-object
replay with the delivered modified proxy, retaining its probe as one additional
DLL export. Its strict baseline comparison excludes only COFF/export timestamps,
clock-matched PGO/ILTCG debug timestamps and the PE checksum; unexplained
differences fail rather than being waived.
Raw baseline/modified outputs are retained even on failure. This experiment
does not load the DLL, run 4D or provide portable corresponding-source delivery.

Run `43299473050` at `63a2c19` built and ingested both real source-candidate
plugins successfully, including Windows with the corrected v143 proxy inputs.
Its Windows replay gate correctly rejected four additional differing bytes:
the timestamp fields in the PGO (type 13) and ILTCG (type 14) debug directories.
Independent inspection of the downloaded originals found equal binary sizes,
equal exports and every other byte equal after the already documented header
normalization. The comparator now accepts only those parsed timestamp fields
when each matches its binary's COFF clock; debug payload bytes and all other
binary bytes remain exact. The original rejected replay is preserved, not
restamped as passing; fresh exact-head native CI remains required.

Independent inspection also caught a Windows inventory destination error that
the downstream source-only package gate would reject: GNU's fresh
`libiconv.lib` was staged under that unused basename, while the actual project
still selected the preserved historical `iconv.lib`. Counts and its supported
1.18 identity were not proof of source selection. The adapter now copies the
verified producer output to the actual `lib/64/iconv.lib` linker path, without
changing declarations/search order or the producer record. A regression covers
staging through actual selected-path promotion. The earlier Windows artifacts
retain their original mixed evidence; they do not establish all-source-selected
coverage. Fresh inventory and native validation must confirm the corrected copy.

Corrected inventory `43302769645` was independently recomputed against the
original kits, including GNU's exact output copied to `iconv.lib`.
Run `43303431095` at `4c5fc81` then passed both actual native builds and the full
Windows modified-library object replay. Its overall green status did not prove
packaging: GitHub skipped the downstream package job through the intentionally
skipped provider ancestors. That job now explicitly evaluates the successful
native result even when those ancestors are skipped. Fresh native/package CI is
required; the earlier run is not container validation.

An independent exported-name comparison against the actual frozen v4.9.10 ZIP
also keeps a compatibility limit explicit. `FourDPackex` (the sole SDK `.def`
entry) and every public C proxy-factory export remain present. Six incidental
libproxy/libmodman C++ names change from by-value to const-reference string
signatures. The plugin itself calls the C factory API; this does not establish
binary compatibility for external C++ callers or separately installed proxy
modules. Such consumers require matching rebuilds or explicit verification
before adoption. No old source revision is inferred from this observation, and
the candidate is not patched to imitate the old C++ ABI.

Run `43305595053` at `ce958b2` subsequently passed both native jobs, Windows'
full modified-library replay and the actual unsigned ZIP/DMG package job.
Every original artifact was downloaded and independently inspected. Both
containers contain the same seven complete bundle files, including the universal
Mac executable and Windows x64 `.4DX`; packaged version metadata is 4.9.10.
All six persisted documents pass official-schema, artifact/binary/slice binding
and cross-format identity/license checks. Independent raw map/log parsing and
the separate selected-package checker confirm 35 named source-record-bound
selections, 32 with supported versions. The ZIP SHA-256 is
`1491b6cca7b3d2a68ec1fdb8d322517699bce0d1ff8d869dddafb66c8ecc878c`;
the DMG SHA-256 is
`4db4af2b74caecc5677c07575f4e559b4cab8acc10dbb77d14fe4202a8436bb3`.
These are representative unsigned validation artifacts, not published release
assets, production adoption, completed license delivery or 4D host proof.

Downloaded originals from `43303431095` independently establish actual
source-record-bound selection for all thirty-five repository archives:
twelve per Mac architecture (eleven versioned) and eleven on Windows (ten
versioned). Twenty-three have the newer compiler/object/archive closure;
the twelve OpenSSL/Brotli bindings still retain their original weaker records.
Windows' full original-object replay and modified-library link both pass.
This result is not portable Windows delivery, container validation or host proof.

`portable_plugin_macos.py` exports a separate Mac source/object-link kit from
the actual isolated project. It includes the unchanged product/SDK source
snapshot, resources, original objects and search-path files, delivered proxy/
modman/iconv source kits and their original records, and the executable helper
code. Each LGPL kit is independently inspected and matched to the actual
selected build record before copying. The generated recipe preserves argument,
object and library order but relocates project inputs; SDK and compiler/linker/
merge-tool identities remain explicit external prerequisites.

```sh
python3 build/dependencies/portable_plugin_macos.py export \
  --project /original/isolated/project --output /fresh/mac-kit
mv /fresh/mac-kit "/different/location/moved mac-kit"
python3 "/different/location/moved mac-kit/tools/build/dependencies/portable_plugin_macos.py" replay \
  --kit "/different/location/moved mac-kit" --output /fresh/baseline-replay
```

Rebuild the delivered proxy source with the kit's `relink_candidate.py` for
each architecture, then repeat `replay` with both `--proxy-arm64` and
`--proxy-x86-64` pointing to the modified `build/libproxy.a` outputs.
Baseline replay requires exact original thin-plugin bytes; modified replay
requires actual defined probe code in both slices and a changed binary.
The helper never initializes the plugin, signs it or installs it in 4D.

Actual relocated-path execution, including a path containing spaces, has
reproduced the original universal plugin and rebuilt both delivered proxy
sources before linking their changes into both full-plugin slices. This closes
the Mac object-link relocation issue, not the whole LGPL delivery gate.
Portable Windows materials and Windows GNU modification/relink verification,
complete notices and remaining-library distribution terms, maintainer-key-free
install/trust and operator-run 4D checks remain open. Unselected search-path
files are retained for link fidelity, not assigned source identities or
declared safe to redistribute; these internal experimental kits are not
release-ready compliance packages.

The delivered `tools/build/dependencies/relink_iconv_macos.py` also rebuilds
GNU iconv from each original delivered source archive with a dated benign
`lib/iconv.c` modification. It preserves the measured configure options and
static/deployment flags, records the actual compatible local toolchain, checks
compiler-object/archive closure and runs all nine baseline conversion/rejection
checks plus the ordered encoding aliases. Its executable probe calls the new
function; `--inspect-only` rechecks the persisted source/recipe/output proof
without running it. GNU configure/build output requires a fresh directory
without whitespace; the source kit itself may be relocated to a spaced path.

```sh
python3 "$KIT/tools/build/dependencies/relink_iconv_macos.py" \
  --candidate "$KIT/library-materials/macos-arm64/libiconv" \
  --output /fresh/no-spaces/iconv-arm64
```

Repeat for `macos-x86_64`, then pass both resulting `build/lib/.libs/libiconv.a`
paths as `--iconv-arm64` and `--iconv-x86-64` to portable `replay`. These may
be combined with the modified proxy arguments. Both delivered GNU source
rebuilds, conversion comparisons and combined full-plugin relinks have been
executed successfully on Mac: both slices retain defined proxy **and** iconv
probe code, with unchanged original product objects and library order.
The experimental combined universal SHA-256 is
`1edda70a20fcf5bb6bf6888eafd879cdea5717233a662efd45718e52a2ab2dce`.
This does not establish modified Windows GNU delivery or 4D host behavior.

The source-plugin-only Windows experiment additionally exports the actual
objects, definition file, source/resources, original GNU/proxy kits and complete
project library-search files with `portable_plugin_windows.py`. It moves that
kit before invoking its delivered helpers, rebuilding modified proxy sources
and attempting the original and modified plugin links. This path requires the
original MSVC linker and selected SDK/CRT archive hashes; proprietary tools are
not redistributed. The recorded unused developer search directory must remain
absent, rather than silently deleting it from the search order. Fresh native
CI and independent persisted-kit inspection must establish this new delivery
path before it is treated as verified. It does not initialize the DLL or 4D.
Run `43312699533` passed the moved Windows execution, but its original uploaded
kit omitted hidden directories, including GNU `.libs` build outputs and product
`.github` recipes. The persisted kit therefore fails its own manifest inspection;
that run is not portable-delivery proof. The upload now includes hidden files,
and a fresh exact-head run and downloaded-kit inspection are required.

The next isolated Windows check rebuilds GNU iconv with the same dated, benign
`iconv_user_relink_probe` change as the Mac demonstration, using
`build_iconv.py build --user-candidate /delivered/original/iconv ...`.
This derives directly from the delivered pristine candidate, retains its source
kit and original build record, records the source delta separately, and compares
all aliases and nine conversion/rejection cases against that source candidate.
The modified probe also calls the new function. Its schema-2
`source-only-user-relink` record cannot enter the normal candidate inventory.
The portable link can accept `--modified-iconv` alongside `--modified-proxy`;
both exports must point into the resulting plugin's own executable code.
The newly acquired job-local GNU tools are outside the uploaded materials;
their acquisition/installed-package records are retained, not their binaries.
Run `43314819192` passed the Windows GNU rebuild and combined full-plugin replay,
but upload encountered an inaccessible GNU `.libs/libiconv.la` convenience
alias. Its on-host result is not persisted-kit proof. Staging now uses the same
narrow `.libs/*.la` omission as the original GNU producer, retaining every hashed
build file, direct archive and original record, with an explicit omission list.
A fresh run and independently inspected downloaded outputs remain required.
`portable_plugin_windows.py inspect` can recheck delivered bytes, baseline
normalization and modified exports on another platform without loading a DLL;
this is not an install/trust or 4D host check.

Run `43317776218` and its independently downloaded kit close that bounded
Windows execution/delivery check: the complete moved kit passes its manifest,
the original-object baseline matches within only the existing clock/checksum
normalization, and the combined modified proxy/GNU plugin contains both defined
probe exports. GNU 1.18's four compiled objects equal the delivered archive's
members; all 198 alias groups and nine conversion/rejection cases agree with
the pristine source candidate. Original rejected uploads remain preserved.
This is still an internal candidate kit, not completed distribution licensing,
source-provider strengthening or a 4D host/install result.

### Fresh provider compiler-material experiments

The `providers` prerequisite scope runs `native-provider-materials.yml` without
building/adopting the plugin, production signing or publishing. It retains the
existing OpenSSL/Brotli record types and adds independently rechecked
`buildMaterials` only after fresh builds. It never enriches historical caches.
Compiler inputs include generated assembly; actual compiled object bytes must
match every installed archive member. The snapshot includes original sources,
generated headers, configuration, original logs, recipes and tool identities.
Unused upstream integration-test gitlinks are explicitly excluded; original
Git symlink text is delivered as checked text records, not followed outside
the source tree.

Local arm64 and x86_64 OpenSSL experiments bind respectively 1,011/1,020 crypto
objects and 94 SSL objects each. Both Brotli targets bind six common, six decoder
and 23 encoder objects; encoder output remains unused by the plugin.
The initial arm64 TLS memory-BIO probe agrees with the original curl-observation
provider kit for authenticated hostname-verified TLS 1.2 and TLS 1.3 application
data. The receipt-backed probe additionally passes wrong-hostname and untrusted
certificate rejection on both macOS architectures: six cases per target.
It retains compiler arguments, exact provider/header/source hashes and original
outputs, and delivers its executed test source and recipe with the root license.
It uses ephemeral in-memory identities, not stored keys or a 4D host; it does not
open a network socket. The isolated provider CI runs the same checks.
These are separate experiments, not new selected-plugin evidence: the twelve
original provider bindings remain weaker until fresh native outputs, consumers
and persisted source records have been verified together.
Windows provider execution and fresh exact-head native CI remain pending.
Physical build/install prefixes and compiler-tracer paths are recorded as
fresh-build configuration, not represented as historical prefix equivalence
or byte-identical reproduction.

Run `43321720349` passed both macOS source-provider builds and their TLS cases.
Its Windows Brotli compilation/tests passed but material inspection correctly
rejected CMake's forward-slash versus compiler-argument backslash spelling.
Windows compiler comparison now normalizes only separators on drive-qualified
paths; it does not conflate different compilers or change source/object bytes.
The same run's OpenSSL configuration selected Git-Bash's incomplete MSYS Perl
before any library compilation. Native Python workflow steps preserve the
Windows tool environment instead, and the builder explicitly requires native
Windows Perl for `VC-WIN64A`. Original rejected output remains rejected.

Run `43323497938` subsequently produced independently inspected Windows Brotli
source/compiler materials: six common, six decoder and 23 encoder objects, all
using release static CRT flags. OpenSSL configuration rejected the attempted
assembler instrumentation before building: upstream ignores the `AS` environment
override with the preserved `-MT` option and quotes its native command names.
The experiment now preserves the original `cl`/`nasm` Configure settings and
supplies tracer commands as explicit NMAKE macro overrides for build/install;
both original commands and configured native tool names are retained.

Fresh proofs check actual compiler deployment/static-CRT flags and every
archive object's CPU and effective Mac minimum, not only requested settings.
Read-only inspection of both persisted Mac kits confirms 1,105/1,114 OpenSSL
objects and 35 Brotli objects per target satisfy those deployment profiles.
For inventory ingestion, full material tables remain in original source kits.
Bounded summaries reference exact original-record hashes; `collect` requires
the corresponding `--provider-source-record` inputs and rechecks them before
accepting aggregated material summaries. Missing originals, changed bytes or
changed summary counts fail. Existing historical records remain unchanged.

```sh
python3 build/dependencies/build_curl.py build \
  --target macos-arm64 --archive /verified/curl-8.21.0.tar.xz \
  --ssh /original/ssh-evidence --zlib /original/zlib-evidence \
  --http /original/nghttp2-evidence --baseline /original/curl-observation \
  --brotli-source /clean/pinned/brotli --output /fresh/curl-evidence
python3 build/dependencies/build_curl.py inspect /downloaded/curl-evidence
```

Dispatch `native-trace.yml` with `native-prerequisites-only=true`,
`native-prerequisite-scope=curl` and `native-provider-run=<original-run-id>`.
Only original successful target-specific producer jobs from an explicitly
dispatched same-repository/branch run are accepted; partial reruns use the latest
attempt of each producer. Unrelated failed jobs do not turn a successful original
prerequisite into a new build record. Source, object, archive and runtime checks
still apply after download. This route has read-only contents/actions permissions
and never builds, signs, packages or publishes the plugin.

libssh2's COPYING text is BSD-3-Clause, but it does not erase embedded
BSD-2-Clause, public-domain or ISC-style notices. In particular,
`bcrypt_pbkdf.c` contains ISC-style permission terms despite its upstream `MIT`
SPDX comment. These original file notices are retained and explicitly inventoried;
public-domain fragments must not be relabeled MIT/CC0. Final normalized license
assertions and redistribution materials still require consolidation.

`native-sources.json` separately pins **release-source acquisitions**, not
selected-production archive identities. Official curl 8.21.0 release source
and signature were verified against the fingerprint published in
[curl's verification instructions](https://curl.se/docs/verify.html).
Its release header reports `8.21.0`; the Git tag's `8.21.0-DEV` banner is a
packaging distinction, not a reason to rewrite an unverified source banner.
The signed release archive is available for the source producer.

### GNU iconv source prerequisites

`build_iconv.py` builds the SHA-pinned GNU 1.16 release archive for each macOS
architecture without replacing production libraries or building the GPL CLI.
Both local architectures preserve the exact ordered 111 encoding groups and
pass nine old/new conversion/rejection checks: Japanese Shift-JIS roundtrip,
ISO-2022-JP flushing, non-BMP UTF-16LE, CP1252, Latin1, invalid/truncated input
and output-buffer exhaustion. This is bounded compatibility evidence, not all
upstream tests or full-plugin validation.

GNU 1.16's configure script enables extra encodings whenever its option is
present, even as `--disable-extra-encodings`. The first experiment exposed
33 extra groups. Omitting that option when the measured baseline lacks extras
restores equality without changing upstream source or weakening the gate.
The exact generated configuration and compiler commands remain in the record.

```sh
python3 build/dependencies/build_iconv.py build \
  --archive /verified/libiconv-1.16.tar.gz --target macos-arm64 \
  --output /fresh/iconv-evidence
python3 build/dependencies/build_iconv.py inspect /downloaded/iconv-evidence
```

The source kit retains the original acquisition tar, exact recipe and source
files, generated interface/configuration, toolchain identities, original
compiler invocations and input/output hashes, all three object payloads,
exact archive-member binding, actual old/new link selections and probe
executables/results. Inspection checks the installed archive/interface/license,
architecture and requested deployment setting. Both downloaded native macOS
outputs from
[run 43267179287](https://github.com/miyako/4d-plugin-curl-v3/actions/runs/43267179287)
were independently inspected without executing downloaded binaries.
The source-only matrix also implements the Windows 1.18 Cygwin/GNU-make/MSVC
recipe. It deliberately requests `/MT`, not
the upstream example's `/MD`; actual compiler settings must prove that choice.
GNU 1.18's compile closure uses `compat.c` and a Windows resource object,
not an assumed copy of the 1.16 macOS source list.
The first Windows experiment measured the old archive independently: 198
groups/670 aliases, extra encodings enabled, and all nine checks passed.
Its candidate configure stopped at the Cygwin-to-native Python executable
path boundary, not a conversion regression; that invocation is corrected for
the next run. The subsequent configure passed; the library build exposed
GNU 1.18's required `lib/localcharset.h` bootstrap target. The recipe runs that
upstream target before the library-only build and distinguishes its unused
helper archive from the four incorporated compiler objects. macOS retains
its separately observed default-off configuration.
All three outputs from
[run 43277456722](https://github.com/miyako/4d-plugin-curl-v3/actions/runs/43277456722)
were downloaded and independently inspected. Windows matches all 198 groups/670
aliases and nine checks with four source/resource-bound archive objects.
Upstream's archiver wrapper resolves the exact recorded MSVC `lib.exe` through
the controlled PATH, avoiding its unquoted handling of a spaced executable path.
Resource execution stays inside Cygwin while native Python records the original
invocation before and after it; command arguments and exit status are preserved.
Inaccessible, unused `.libs/*.la` convenience aliases are omitted from the upload
view, with their names, direct metadata and original build logs retained.
Shared JSON probe helpers have explicit recipe contracts so earlier curl/SSH
records remain inspectable with their original delivered recipes.

```sh
python build/dependencies/prepare_cygwin.py --output /fresh/cygwin-tools
python build/dependencies/build_iconv.py build \
  --archive /verified/libiconv-1.18.tar.gz --target windows-x86_64 \
  --cygwin-root /fresh/cygwin-tools/root --output /fresh/iconv-evidence
```

Preparation is Windows-only and job-local. The installer hash matches the
official SHA-512 listing and its preserved signature was verified against
the key published by Cygwin; a changed installer is rejected before execution.
Repository signature checking is not disabled. Resolved package versions,
setup records and individual compiler/resource/tool identities are retained.
The Cygwin environment is a build prerequisite, not a linked plugin dependency
or an MSYS2 substitute. Tool binaries are not bundled into the source kit.

Both original GNU libiconv source archives/signatures and the official GNU
public keyring are preserved. Signature verification reports `VALIDSIG` with
expired-key warnings; both signatures predate the observed key expiries.
This is not a current key-trust endorsement. `COPYING.LIB` and the library's
`iconv.c` specify LGPL-2.1-or-later; root GPL tool terms must not indiscriminately
be assigned to the library or ignored for tools actually redistributed.
Upstream's MSVC instructions require Cygwin/GNU make with the supplied compiler
and archive wrappers, not nmake or MSYS2. A static-CRT recipe, actual encoding/
conversion comparison and corresponding-source/relink delivery remain necessary;
neither source acquisition nor identifying LGPL text satisfies those gates.

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
