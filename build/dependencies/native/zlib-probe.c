#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zlib.h"

static void require(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void filename(char *result, size_t capacity, const char *directory, const char *name) {
    int length = snprintf(result, capacity, "%s/%s", directory, name);
    require(length >= 0 && (size_t)length < capacity, "fixture path too long");
}

static void decode(const unsigned char *encoded, size_t length, int window,
                   const unsigned char *expected, size_t expected_length, int valid) {
    z_stream stream;
    unsigned char result[65536];
    int status;
    memset(&stream, 0, sizeof(stream));
    require(inflateInit2(&stream, window) == Z_OK, "initialize inflate");
    stream.next_in = (Bytef *)encoded;
    stream.avail_in = (uInt)length;
    stream.next_out = result;
    stream.avail_out = sizeof(result);
    status = inflate(&stream, Z_FINISH);
    if (valid)
        require(status == Z_STREAM_END && stream.total_in == length &&
            stream.total_out == expected_length &&
            memcmp(result, expected, expected_length) == 0, "cross-library inflate contents");
    else
        require(status != Z_STREAM_END, "truncated stream unexpectedly accepted");
    require(inflateEnd(&stream) == Z_OK, "finish inflate");
}

int main(int argc, char **argv) {
    unsigned char payload[8192], encoded[65536];
    const int windows[] = {15, -15, 31};
    const char *names[] = {"zlib.bin", "raw.bin", "gzip.bin"};
    char path[4096];
    size_t i;
    int format, writing;
    require(argc == 3, "expected write/read and fixture directory");
    writing = strcmp(argv[1], "write") == 0;
    require(writing || strcmp(argv[1], "read") == 0, "unknown probe mode");
    require(strcmp(zlibVersion(), EXPECTED_ZLIB_VERSION) == 0, "unexpected zlib runtime version");
    require(crc32(0, (const Bytef *)"123456789", 9) == 0xcbf43926UL, "CRC32 check");
    require(adler32(1, (const Bytef *)"123456789", 9) == 0x091e01deUL, "Adler32 check");
    for (i = 0; i < sizeof(payload); ++i)
        payload[i] = (unsigned char)((i * 37 + i / 17) & 255);
    for (format = 0; format < 3; ++format) {
        FILE *file;
        size_t length;
        filename(path, sizeof(path), argv[2], names[format]);
        if (writing) {
            z_stream stream;
            memset(&stream, 0, sizeof(stream));
            require(deflateInit2(&stream, 6, Z_DEFLATED, windows[format], 8,
                Z_DEFAULT_STRATEGY) == Z_OK, "initialize deflate");
            stream.next_in = payload;
            stream.avail_in = sizeof(payload);
            stream.next_out = encoded;
            stream.avail_out = sizeof(encoded);
            require(deflate(&stream, Z_FINISH) == Z_STREAM_END, "finish deflate");
            length = stream.total_out;
            require(deflateEnd(&stream) == Z_OK, "release deflate");
            file = fopen(path, "wb");
            require(file != NULL, "create compressed fixture");
            require(fwrite(encoded, 1, length, file) == length, "write compressed fixture");
            require(fclose(file) == 0, "close compressed fixture");
        } else {
            file = fopen(path, "rb");
            require(file != NULL, "open peer compressed fixture");
            length = fread(encoded, 1, sizeof(encoded), file);
            require(length > 1 && feof(file) && !ferror(file), "read peer compressed fixture");
            require(fclose(file) == 0, "close peer compressed fixture");
            decode(encoded, length, windows[format], payload, sizeof(payload), 1);
            decode(encoded, length - 1, windows[format], payload, sizeof(payload), 0);
        }
    }
    if (writing) {
        FILE *file;
        filename(path, sizeof(path), argv[2], "version-info.json");
        file = fopen(path, "wb");
        require(file != NULL, "create runtime observations");
        require(fprintf(file, "{\"version\":\"%s\",\"compileFlags\":%lu}\n",
            zlibVersion(), zlibCompileFlags()) > 0, "write runtime observations");
        require(fclose(file) == 0, "close runtime observations");
    }
    printf("%s %s: zlib/raw/gzip, checksums and truncation checks passed; compileFlags=%lu\n",
        zlibVersion(), argv[1], zlibCompileFlags());
    return 0;
}
