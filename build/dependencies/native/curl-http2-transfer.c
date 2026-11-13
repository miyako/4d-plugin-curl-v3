#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
#include <curl/curl.h>

int main(int argc, char **argv)
{
    CURL *easy = NULL;
    CURLcode code = CURLE_FAILED_INIT;
    unsigned char *upload = NULL;
    long status = 0, version = 0, length = 0;
    int result = 2;
    if (argc != 6 || (strcmp(argv[3], "h2c") && strcmp(argv[3], "1.2")
                     && strcmp(argv[3], "1.3"))) {
        fprintf(stderr, "Expected URL, CA file, h2c/TLS version, upload file or - and encoding\n");
        return 2;
    }
#ifdef _WIN32
    if (_setmode(_fileno(stdout), _O_BINARY) == -1)
        return 2;
#endif
    if (strcmp(argv[4], "-")) {
        FILE *input = fopen(argv[4], "rb");
        if (!input) {
            perror("Cannot open HTTP/2 upload fixture");
            return 2;
        }
        if (fseek(input, 0, SEEK_END) || (length = ftell(input)) < 1
            || length > 1024 * 1024 || fseek(input, 0, SEEK_SET)
            || !(upload = (unsigned char *)malloc((size_t)length))) {
            fprintf(stderr, "Invalid or unallocatable bounded HTTP/2 upload fixture\n");
            fclose(input);
            return 2;
        }
        {
            size_t received = fread(upload, 1, (size_t)length, input);
            int closed = fclose(input);
            if (received != (size_t)length || closed) {
                fprintf(stderr, "Cannot read complete HTTP/2 upload fixture\n");
                free(upload);
                return 2;
            }
        }
    }
    if (curl_global_sslset(CURLSSLBACKEND_NONE, "openssl", NULL) != CURLSSLSET_OK
        || curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        fprintf(stderr, "Cannot initialize the standalone HTTP/2 OpenSSL backend\n");
        free(upload);
        return 2;
    }
    easy = curl_easy_init();
    if (!easy) {
        fprintf(stderr, "Cannot create a standalone HTTP/2 transfer\n");
        goto finished;
    }
#define SET(option, value) do { \
    code = curl_easy_setopt(easy, option, value); \
    if (code != CURLE_OK) goto finished; \
} while (0)
    SET(CURLOPT_URL, argv[1]);
    SET(CURLOPT_PROXY, "");
    SET(CURLOPT_CONNECTTIMEOUT, 5L);
    SET(CURLOPT_TIMEOUT, 15L);
    SET(CURLOPT_NOSIGNAL, 1L);
    SET(CURLOPT_HTTP_VERSION, (long)(!strcmp(argv[3], "h2c")
        ? CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE : CURL_HTTP_VERSION_2TLS));
    SET(CURLOPT_ACCEPT_ENCODING, argv[5]);
    SET(CURLOPT_SSL_VERIFYPEER, 1L);
    SET(CURLOPT_SSL_VERIFYHOST, 2L);
    if (strcmp(argv[2], "-"))
        SET(CURLOPT_CAINFO, argv[2]);
    if (strcmp(argv[3], "h2c"))
        SET(CURLOPT_SSLVERSION, !strcmp(argv[3], "1.2")
            ? (long)(CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_TLSv1_2)
            : (long)(CURL_SSLVERSION_TLSv1_3 | CURL_SSLVERSION_MAX_TLSv1_3));
    if (upload) {
        SET(CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)length);
        SET(CURLOPT_POSTFIELDS, upload);
    }
    code = curl_easy_perform(easy);
    if (curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK
        || curl_easy_getinfo(easy, CURLINFO_HTTP_VERSION, &version) != CURLE_OK) {
        fprintf(stderr, "Cannot read standalone HTTP/2 transfer metadata\n");
        goto finished;
    }
    result = code == CURLE_OK && status == 200 && version == CURL_HTTP_VERSION_2_0 ? 0 : 1;
finished:
    fprintf(stderr, "{\"curlCode\":%d,\"httpStatus\":%ld,\"httpVersion\":%ld}\n",
            (int)code, status, version);
    if (easy)
        curl_easy_cleanup(easy);
    curl_global_cleanup();
    free(upload);
    return result;
}
