#include "ufopen.h"

#ifndef struct_stat
#  define struct_stat struct stat
#endif

/*
 * patch to use utf-8 paths on windows instead of ANSI
 *
 */
FILE *ufopen(const char *filename, const char *mode)
{
#ifdef _WIN32
    wchar_t	buf[_MAX_PATH];
    wchar_t	_wfmode[99];    //should be enough
    if(MultiByteToWideChar(CP_UTF8, 0, mode, -1, (LPWSTR)_wfmode, 99))
    {
        if(MultiByteToWideChar(CP_UTF8, 0, filename, -1, (LPWSTR)buf, _MAX_PATH))
        {
            return _wfopen((const wchar_t *)buf, (const wchar_t *)_wfmode);
        }
    }
    return  fopen(filename, mode);
#else 
    return fopen(filename, mode);
#endif
}

#ifdef _WIN32
#else
#include <sys/fcntl.h>
#endif

int uopen(const char *filename, int mode)
{
#ifdef _WIN32
    wchar_t	buf[_MAX_PATH];
    if(MultiByteToWideChar(CP_UTF8, 0, filename, -1, (LPWSTR)buf, _MAX_PATH))
    {
        return _wopen((const wchar_t *)buf, mode);
    }
    return 0;
#else
    return open(filename, mode);
#endif
}
#ifdef _WIN32
int ustati64(const char *path, struct _stati64 *buffer)
{

    wchar_t	buf[_MAX_PATH];
    if(MultiByteToWideChar(CP_UTF8, 0, path, -1, (LPWSTR)buf, _MAX_PATH))
    {
        return _wstati64((const wchar_t *)buf, buffer);
    }
	return -1;
}
#endif
