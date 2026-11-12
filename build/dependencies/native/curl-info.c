#include <stdio.h>
#include "curl/curl.h"

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

int main(void) {
    curl_version_info_data *info;
    CURLcode status = curl_global_init(CURL_GLOBAL_DEFAULT);
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
    field("rtmpVersion", info->librtmp_version);
    field("cainfo", info->cainfo);
    field("capath", info->capath);
    fputs("}\n", stdout);
    curl_global_cleanup();
    return 0;
}
