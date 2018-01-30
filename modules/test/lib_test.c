/* 
 *  bugficks
 *	(c) 2013
 *
 */
//////////////////////////////////////////////////////////////////////////////

#define _XOPEN_SOURCE  500
#include <stdio.h>
#include <stdarg.h>
#include <limits.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

//////////////////////////////////////////////////////////////////////////////

#define LOG_FILE    "/tmp/lib_test.log"

//////////////////////////////////////////////////////////////////////////////

static void LOG(
        const char *fmt, ...)
{
#ifdef LOG_FILE
    va_list ap;
    
    FILE *f = fopen(LOG_FILE, "a+");
    if(f)
    {
        va_start(ap, fmt);
        vfprintf(f, fmt, ap);
        va_end(ap);
        
        fflush(f); 
        fclose(f); 
    }
#endif    
}

//////////////////////////////////////////////////////////////////////////////

int getArgCArgV(
        void *mem, char **argv) 
{
    const int EXTRA_COOKIE = 0x82374021;

    uint32_t aligned = (uint32_t)mem;
    aligned = (aligned + 3) & ~3;

    uint32_t *extra = (uint32_t*)aligned;
    if(extra[0] != EXTRA_COOKIE)
        return 0;

    uint32_t argc = extra[1];
    uint32_t *_argv = &extra[2];
    for(int i = 0; i < argc; i++)
        argv[i] = (char *)(aligned + _argv[i]);
    
    return argc;
}

//////////////////////////////////////////////////////////////////////////////

void lib_init(
        void *h, const char *libpath)
{
    char *argv[100];
    void *p = (void*)(libpath + strlen(libpath) + 1);
    int argc = getArgCArgV(p, argv);

    LOG("<%s> h: %p, libpath: %s\n", __func__, h, libpath);
    LOG("<%s> argc = %d, argv = %p\n", __func__, argc, argv);
    for(int i = 0; i < argc; i++)
    {
        LOG("<%s> argv[%d] = %s\n", __func__, i, argv[i]);
    }
}

void lib_deinit(
        void *h)
{
    LOG("<%s> h: %p \n", __func__, h);
}

//////////////////////////////////////////////////////////////////////////////
