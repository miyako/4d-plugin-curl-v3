#include <errno.h>
#include <iconv.h>
#include <string.h>
#include "probe-json.h"

static int aliases(unsigned int count, const char *const *names, void *data) {
    unsigned int i;
    int *first = (int *)data;
    if (!*first) putchar(',');
    *first = 0;
    putchar('[');
    for (i = 0; i < count; ++i) {
        if (i) putchar(',');
        string(names[i]);
    }
    putchar(']');
    return 0;
}

static int conversion(const char *to, const char *from, const unsigned char *input,
                      size_t size, const unsigned char *expected, size_t expected_size) {
    iconv_t converter = iconv_open(to, from);
    char *in = (char *)input;
    unsigned char output[128];
    char *out = (char *)output;
    size_t left = size, available = sizeof(output);
    int failed;
    if (converter == (iconv_t)-1) {
        fprintf(stderr, "iconv_open(%s, %s) failed: %d\n", to, from, errno);
        return 1;
    }
    failed = iconv(converter, &in, &left, &out, &available) == (size_t)-1 || left
        || iconv(converter, NULL, NULL, &out, &available) == (size_t)-1
        || sizeof(output) - available != expected_size
        || memcmp(output, expected, expected_size);
    if (iconv_close(converter)) failed = 1;
    if (failed) fprintf(stderr, "conversion %s -> %s did not match\n", from, to);
    return failed;
}

static int rejection(const unsigned char *input, size_t size, size_t capacity, int expected) {
    iconv_t converter = iconv_open("UTF-16LE", "UTF-8");
    char *in = (char *)input;
    unsigned char output[32];
    char *out = (char *)output;
    size_t left = size, available = capacity, result;
    int error, failed;
    if (converter == (iconv_t)-1) {
        fputs("cannot open rejection-test converter\n", stderr);
        return 1;
    }
    errno = 0;
    result = iconv(converter, &in, &left, &out, &available);
    error = errno;
    failed = result != (size_t)-1 || error != expected || left != size;
    if (iconv_close(converter)) failed = 1;
    if (failed) fprintf(stderr, "iconv rejection expected errno %d, received %d\n", expected, error);
    return failed;
}

int main(void) {
    static const unsigned char utf8[] = {0xe6, 0x97, 0xa5, 0xe6, 0x9c, 0xac, 0xe8, 0xaa, 0x9e};
    static const unsigned char sjis[] = {0x93, 0xfa, 0x96, 0x7b, 0x8c, 0xea};
    static const unsigned char iso2022[] = {
        0x1b, 0x24, 0x42, 0x46, 0x7c, 0x4b, 0x5c, 0x38, 0x6c, 0x1b, 0x28, 0x42};
    static const unsigned char nonbmp[] = {0xf0, 0x9f, 0x98, 0x80};
    static const unsigned char utf16[] = {0x3d, 0xd8, 0x00, 0xde};
    static const unsigned char euro[] = {0xe2, 0x82, 0xac}, cp1252[] = {0x80};
    static const unsigned char accent[] = {0xc3, 0xa9}, latin1[] = {0xe9};
    static const unsigned char invalid[] = {0xc3, 0x28}, truncated[] = {0xe6, 0x97};
    int first = 1;
    if (conversion("SHIFT_JIS", "UTF-8", utf8, sizeof(utf8), sjis, sizeof(sjis))
        || conversion("UTF-8", "SHIFT_JIS", sjis, sizeof(sjis), utf8, sizeof(utf8))
        || conversion("ISO-2022-JP", "UTF-8", utf8, sizeof(utf8), iso2022, sizeof(iso2022))
        || conversion("UTF-16LE", "UTF-8", nonbmp, sizeof(nonbmp), utf16, sizeof(utf16))
        || conversion("CP1252", "UTF-8", euro, sizeof(euro), cp1252, sizeof(cp1252))
        || conversion("ISO-8859-1", "UTF-8", accent, sizeof(accent), latin1, sizeof(latin1))
        || rejection(invalid, sizeof(invalid), 32, EILSEQ)
        || rejection(truncated, sizeof(truncated), 32, EINVAL)
        || rejection(nonbmp, sizeof(nonbmp), 1, E2BIG))
        return 1;
    printf("{\"version\":\"%d.%d\",\"aliases\":[",
           (_libiconv_version >> 8) & 255, _libiconv_version & 255);
    iconvlist(aliases, &first);
    fputs("],\"checks\":[\"shift-jis\",\"shift-jis-roundtrip\",\"iso-2022-jp-flush\","
          "\"non-bmp-utf16\",\"cp1252\",\"latin1\",\"invalid-input\","
          "\"truncated-input\",\"small-output\"]}\n", stdout);
    return 0;
}
