#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
#include <curl/curl.h>

int main(int argc, char **argv)
{
    CURL *easy;
    CURLcode code;
    long status = 0;
    long tls_version;
    if (argc != 7 || (strcmp(argv[5], "1.2") && strcmp(argv[5], "1.3"))) {
        fprintf(stderr, "Expected backend, URL, CA file, proxy, TLS version and encoding\n");
        return 2;
    }
#ifdef _WIN32
    if (_setmode(_fileno(stdout), _O_BINARY) == -1)
        return 2;
#endif
    if (curl_global_sslset(CURLSSLBACKEND_NONE, argv[1], NULL) != CURLSSLSET_OK
        || curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        fprintf(stderr, "Cannot initialize the requested standalone curl backend\n");
        return 2;
    }
    easy = curl_easy_init();
    if (!easy) {
        fprintf(stderr, "Cannot create a standalone curl transfer\n");
        curl_global_cleanup();
        return 2;
    }
#define SET(option, value) do { \
    code = curl_easy_setopt(easy, option, value); \
    if (code != CURLE_OK) goto finished; \
} while (0)
    SET(CURLOPT_URL, argv[2]);
    SET(CURLOPT_PROXY, strcmp(argv[4], "-") ? argv[4] : "");
    SET(CURLOPT_NOPROXY, "");
    SET(CURLOPT_CONNECTTIMEOUT, 5L);
    SET(CURLOPT_TIMEOUT, 15L);
    SET(CURLOPT_NOSIGNAL, 1L);
    SET(CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_1_1);
    SET(CURLOPT_ACCEPT_ENCODING, argv[6]);
    SET(CURLOPT_SSL_VERIFYPEER, 1L);
    SET(CURLOPT_SSL_VERIFYHOST, 2L);
    if (strcmp(argv[3], "-"))
        SET(CURLOPT_CAINFO, argv[3]);
    tls_version = !strcmp(argv[5], "1.3")
        ? CURL_SSLVERSION_TLSv1_3 | CURL_SSLVERSION_MAX_TLSv1_3
        : CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_TLSv1_2;
    SET(CURLOPT_SSLVERSION, tls_version);
    if (!strcmp(argv[1], "schannel")) {
        /* The isolated self-signed fixture has no revocation infrastructure. */
        SET(CURLOPT_SSL_OPTIONS, (long)CURLSSLOPT_NO_REVOKE);
    }
    code = curl_easy_perform(easy);
    if (curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK) {
        fprintf(stderr, "Cannot read the transfer status\n");
        curl_easy_cleanup(easy);
        curl_global_cleanup();
        return 2;
    }
finished:
    fprintf(stderr, "{\"curlCode\":%d,\"httpStatus\":%ld}\n", (int)code, status);
    curl_easy_cleanup(easy);
    curl_global_cleanup();
    return (int)code;
}
