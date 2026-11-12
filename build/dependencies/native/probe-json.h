#ifndef NATIVE_PROBE_JSON_H
#define NATIVE_PROBE_JSON_H

#include <stdio.h>

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

#endif
