#include <stdio.h>
#ifndef SSH_ONLY
#include "curl/curl.h"
#endif
#include "libssh2.h"

static void string(const char *text) {
    const unsigned char *p;
    if (!text) {
        fputs("null", stdout);
        return;
    }
    putchar('"');
    for (p = (const unsigned char *)text; *p; ++p) {
        if (*p == '"' || *p == '\\')
            printf("\\%c", *p);
        else if (*p < 32)
            printf("\\u%04x", (unsigned int)*p);
        else
            putchar(*p);
    }
    putchar('"');
}

static void array(const char *const *items) {
    int first = 1;
    putchar('[');
    while (items && *items) {
        if (!first) putchar(',');
        string(*items++);
        first = 0;
    }
    putchar(']');
}

static void field(const char *name, const char *value) {
    putchar(',');
    string(name);
    putchar(':');
    string(value);
}

static int ssh_algorithms(void) {
    static const int methods[] = {
        LIBSSH2_METHOD_KEX, LIBSSH2_METHOD_HOSTKEY,
        LIBSSH2_METHOD_CRYPT_CS, LIBSSH2_METHOD_CRYPT_SC,
        LIBSSH2_METHOD_MAC_CS, LIBSSH2_METHOD_MAC_SC,
        LIBSSH2_METHOD_COMP_CS, LIBSSH2_METHOD_COMP_SC
    };
    static const char *names[] = {
        "kex", "hostkey", "cipherClientToServer", "cipherServerToClient",
        "macClientToServer", "macServerToClient",
        "compressionClientToServer", "compressionServerToClient"
    };
    LIBSSH2_SESSION *session;
    unsigned int i;
    int status = libssh2_init(0);
    if (status) {
        fprintf(stderr, "libssh2_init failed: %d\n", status);
        return 1;
    }
    session = libssh2_session_init();
    if (!session) {
        fputs("libssh2_session_init failed\n", stderr);
        libssh2_exit();
        return 1;
    }
    fputs(",\"sshAlgorithms\":{", stdout);
    for (i = 0; i < sizeof(methods) / sizeof(methods[0]); ++i) {
        const char **algorithms = NULL;
        int j, count = libssh2_session_supported_algs(session, methods[i], &algorithms);
        if (count <= 0) {
            fprintf(stderr, "libssh2_session_supported_algs(%s) failed: %d\n", names[i], count);
            libssh2_session_free(session);
            libssh2_exit();
            return 1;
        }
        if (i) putchar(',');
        string(names[i]);
        fputs(":[", stdout);
        for (j = 0; j < count; ++j) {
            if (j) putchar(',');
            string(algorithms[j]);
        }
        putchar(']');
        libssh2_free(session, algorithms);
    }
    putchar('}');
    libssh2_session_free(session);
    libssh2_exit();
    return 0;
}

int main(void) {
#ifdef SSH_ONLY
    fputs("{\"version\":", stdout);
    string(libssh2_version(0));
    if (ssh_algorithms()) return 1;
    fputs("}\n", stdout);
    return 0;
#else
    const curl_ssl_backend **backends = NULL;
    CURLsslset backend_status = curl_global_sslset(CURLSSLBACKEND_NONE, NULL, &backends);
    unsigned int i;
    curl_version_info_data *info;
    CURLcode status;
    if (backend_status != CURLSSLSET_UNKNOWN_BACKEND || !backends || !backends[0]) {
        fprintf(stderr, "TLS backend enumeration failed: %d\n", (int)backend_status);
        return 1;
    }
    status = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (status != CURLE_OK) {
        fprintf(stderr, "curl_global_init failed: %s\n", curl_easy_strerror(status));
        return 1;
    }
    info = curl_version_info(CURLVERSION_NOW);
    if (!info || info->age < CURLVERSION_TWELFTH) {
        fputs("curl version interface is older than the frozen baseline\n", stderr);
        curl_global_cleanup();
        return 1;
    }
    fputs("{\"version\":", stdout);
    string(info->version);
    printf(",\"versionNumber\":%u,\"featuresMask\":%u,\"features\":",
           info->version_num, (unsigned int)info->features);
    array(info->feature_names);
    fputs(",\"protocols\":", stdout);
    array(info->protocols);
    field("host", info->host);
    field("sslVersion", info->ssl_version);
    field("libzVersion", info->libz_version);
    field("libsshVersion", info->libssh_version);
    field("nghttp2Version", info->nghttp2_version);
    field("quicVersion", info->quic_version);
    field("brotliVersion", info->brotli_version);
    field("zstdVersion", info->zstd_version);
    field("aresVersion", info->ares);
    field("idnVersion", info->libidn);
    field("rtmpVersion", info->rtmp_version);
    field("cainfo", info->cainfo);
    field("capath", info->capath);
    fputs(",\"tlsBackends\":[", stdout);
    for (i = 0; backends[i]; ++i) {
        if (i) putchar(',');
        string(backends[i]->name);
    }
    putchar(']');
    if (ssh_algorithms()) {
        curl_global_cleanup();
        return 1;
    }
    fputs("}\n", stdout);
    curl_global_cleanup();
    return 0;
#endif
}
