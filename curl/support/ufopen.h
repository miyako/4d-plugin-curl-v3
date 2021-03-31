#ifndef ufopen_h
#define ufopen_h

#if defined(_WIN32)
#include <sys/types.h>
#include <sys/stat.h>
#include <io.h>
#include <windows.h>
#endif
#include <stdio.h>

FILE *ufopen(const char *filename, const char *mode);
int uopen(const char *filename, int mode);
int ustati64(const char *path, struct _stati64 *buffer);

#endif /* ufopen_h */
