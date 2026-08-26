#!/usr/bin/env bash
# Builds a universal (arm64 + x86_64) static libcurl for macOS via vcpkg,
# matching the feature set resolved for the Windows build:
#
#   curl[brotli,core,http2,non-http,openssl,ssh,ssl,sspi]:x64-windows-static
#     -> brotli, core, http2, non-http, openssl, ssh, ssl
#        (sspi/schannel/winssl dropped - Windows-only TLS backends;
#        openssl is the TLS backend on macOS too)
#
# Deliberately excludes (matching the Windows resolution, which also
# excluded them): c-ares, zstd, idn2/unistring, and the QUIC/HTTP-3
# stack (ngtcp2, nghttp3, ngtcp2_crypto_ossl). If you need any of
# those, add the matching feature to FEATURES below.
#
# Pins the same versions vcpkg resolved for Windows, so both platforms
# link against byte-identical dependency versions rather than "close
# enough" ones that could reintroduce subtle ABI drift:
#   curl 8.21.0, libssh2 1.11.1, nghttp2 1.70.0, openssl 3.6.3,
#   zlib 1.3.2, brotli 1.2.0
#
# Usage: ./build-libcurl-macos.sh [output-dir]
# Requires: git, cmake, ninja (or make), a working C/C++ toolchain (Xcode CLT)
set -euo pipefail

OUT_DIR="${1:-$(pwd)/libcurl-macos-out}"
WORK_DIR="$(mktemp -d)"
FEATURES="brotli,core,http2,non-http,openssl,ssh,ssl"

echo "Working in: $WORK_DIR"
echo "Output to:  $OUT_DIR"
mkdir -p "$OUT_DIR"

# ---- 1. Bootstrap vcpkg ----
git clone --depth 1 https://github.com/microsoft/vcpkg.git "$WORK_DIR/vcpkg"
"$WORK_DIR/vcpkg/bootstrap-vcpkg.sh" -disableMetrics

# "overrides" requires a "builtin-baseline" to anchor against - use the
# exact commit of the vcpkg checkout above rather than hardcoding one,
# so this stays correct as vcpkg itself is updated.
BASELINE="$(git -C "$WORK_DIR/vcpkg" rev-parse HEAD)"
echo "Using builtin-baseline: $BASELINE"

# ---- 2. Manifest pinning exact versions ----
# "overrides" forces these exact versions regardless of vcpkg's current
# baseline, so this stays reproducible even as the vcpkg registry moves on.
mkdir -p "$WORK_DIR/manifest"
cat > "$WORK_DIR/manifest/vcpkg.json" <<EOF
{
  "name": "4d-plugin-curl-deps",
  "version-string": "1.0.0",
  "builtin-baseline": "$BASELINE",
  "dependencies": [
    { "name": "curl", "default-features": false, "features": ["brotli", "http2", "non-http", "openssl", "ssh", "ssl"] }
  ],
  "overrides": [
    { "name": "curl", "version": "8.21.0", "port-version": 1 },
    { "name": "libssh2", "version": "1.11.1", "port-version": 3 },
    { "name": "nghttp2", "version": "1.70.0" },
    { "name": "openssl", "version": "3.6.3" },
    { "name": "zlib", "version": "1.3.2", "port-version": 2 },
    { "name": "brotli", "version": "1.2.0" }
  ]
}
EOF

# ---- 3. Static triplets ----
# vcpkg's built-in osx triplets default to dynamic linkage; the plugin
# needs static .a archives, so define custom triplets explicitly.
mkdir -p "$WORK_DIR/triplets"
cat > "$WORK_DIR/triplets/arm64-osx-static.cmake" <<'EOF'
set(VCPKG_TARGET_ARCHITECTURE arm64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_CMAKE_SYSTEM_NAME Darwin)
set(VCPKG_OSX_ARCHITECTURES arm64)
EOF
cat > "$WORK_DIR/triplets/x64-osx-static.cmake" <<'EOF'
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_CMAKE_SYSTEM_NAME Darwin)
set(VCPKG_OSX_ARCHITECTURES x86_64)
EOF

VCPKG="$WORK_DIR/vcpkg/vcpkg"

# ---- 4. Build for each architecture ----
for TRIPLET in arm64-osx-static x64-osx-static; do
  echo "=== Building for $TRIPLET ==="
  "$VCPKG" install \
    --x-manifest-root="$WORK_DIR/manifest" \
    --x-install-root="$WORK_DIR/installed-$TRIPLET" \
    --overlay-triplets="$WORK_DIR/triplets" \
    --triplet="$TRIPLET" \
    --clean-after-build
done

# ---- 5. Merge into universal static libs ----
LIB_ARM64="$WORK_DIR/installed-arm64-osx-static/arm64-osx-static/lib"
LIB_X64="$WORK_DIR/installed-x64-osx-static/x64-osx-static/lib"

echo "=== Merging into universal libs ==="
for LIBNAME in libcurl.a libssl.a libcrypto.a libssh2.a libnghttp2.a \
               libz.a libbrotlicommon.a libbrotlidec.a libbrotlienc.a; do
  if [[ -f "$LIB_ARM64/$LIBNAME" && -f "$LIB_X64/$LIBNAME" ]]; then
    lipo -create "$LIB_ARM64/$LIBNAME" "$LIB_X64/$LIBNAME" -output "$OUT_DIR/$LIBNAME"
    echo "  merged $LIBNAME"
    lipo -info "$OUT_DIR/$LIBNAME"
  else
    echo "  !! skipping $LIBNAME - not found in one or both triplet outputs" >&2
  fi
done

echo
echo "Done. Universal static libs are in: $OUT_DIR"
echo "Next steps:"
echo "  1. Copy these into the repo's a/ directory, replacing the old vendored libs."
echo "  2. Remove now-unused libs from a/ and from project.pbxproj's file"
echo "     references + Frameworks build phase: libcares.a, libzstd.a,"
echo "     libidn2.a, libunistring.a, libngtcp2*.a, libnghttp3.a (this build"
echo "     doesn't link any of them, matching the Windows vcpkg resolution)."
echo "  3. Update the Windows .vcxproj's AdditionalDependencies to drop the"
echo "     same libs, so both platforms link the same trimmed dependency set."
echo "  4. Point release.yml's OpenSSL-from-source step at openssl-3.6.3 on"
echo "     BOTH platforms, so the final linked OpenSSL matches what this"
echo "     libcurl was actually built against."
