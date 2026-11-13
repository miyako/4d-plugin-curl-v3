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
    FILE *input = NULL;
    if (argc != 7) {
        fprintf(stderr, "Expected URL, known hosts, username, password, operation and input\n");
        return 2;
    }
#ifdef _WIN32
    if (_setmode(_fileno(stdout), _O_BINARY) == -1)
        return 2;
#endif
    if (strcmp(argv[5], "download") && strcmp(argv[5], "upload")) {
        fprintf(stderr, "Unknown SSH fixture operation\n");
        return 2;
    }
    if (curl_global_sslset(CURLSSLBACKEND_NONE, "openssl", NULL) != CURLSSLSET_OK
        || curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        fprintf(stderr, "Cannot initialize the standalone SSH transfer\n");
        return 2;
    }
    easy = curl_easy_init();
    if (!easy) {
        fprintf(stderr, "Cannot create the standalone SSH transfer\n");
        curl_global_cleanup();
        return 2;
    }
#define SET(option, value) do { \
    code = curl_easy_setopt(easy, option, value); \
    if (code != CURLE_OK) goto finished; \
} while (0)
    SET(CURLOPT_URL, argv[1]);
    SET(CURLOPT_PROXY, "");
    SET(CURLOPT_NOPROXY, "");
    SET(CURLOPT_CONNECTTIMEOUT, 5L);
    SET(CURLOPT_TIMEOUT, 15L);
    SET(CURLOPT_NOSIGNAL, 1L);
    SET(CURLOPT_PROTOCOLS_STR, "sftp,scp");
    SET(CURLOPT_USERNAME, argv[3]);
    SET(CURLOPT_PASSWORD, argv[4]);
    SET(CURLOPT_SSH_AUTH_TYPES, (long)CURLSSH_AUTH_PASSWORD);
    SET(CURLOPT_SSH_KNOWNHOSTS, argv[2]);
    if (!strcmp(argv[5], "upload")) {
        long length;
        input = fopen(argv[6], "rb");
        if (!input || fseek(input, 0, SEEK_END) != 0
            || (length = ftell(input)) < 0 || fseek(input, 0, SEEK_SET) != 0) {
            fprintf(stderr, "Cannot read the bounded SSH fixture payload\n");
            if (input) fclose(input);
            curl_easy_cleanup(easy);
            curl_global_cleanup();
            return 2;
        }
        SET(CURLOPT_UPLOAD, 1L);
        SET(CURLOPT_READDATA, input);
        SET(CURLOPT_INFILESIZE_LARGE, (curl_off_t)length);
    }
    code = curl_easy_perform(easy);
finished:
    fprintf(stderr, "{\"curlCode\":%d}\n", (int)code);
    if (input) fclose(input);
    curl_easy_cleanup(easy);
    curl_global_cleanup();
    return (int)code;
}
