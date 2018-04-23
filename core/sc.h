/* 
 * shellcode for arm
 *
 *  bugficks
 *	(c) 2013
 *
 *  License: GPLv3
 *
 */

//////////////////////////////////////////////////////////////////////////////

#define _GNU_SOURCE

#include <stdint.h>
#include <stddef.h>
#include <dlfcn.h>

//////////////////////////////////////////////////////////////////////////////

typedef struct 
{
    void* (*dlopen)(const char*,int);
    void* (*dlsym)(void*, const char*);
    int (*dlclose)(void*);
    void *lib;
    void *fn_init;
    void *fn_deinit;
    char lib_init[16];
    char lib_deinit[16];
    char lib_name[];
} sc_ctx_t;

//////////////////////////////////////////////////////////////////////////////

typedef struct
{
    uint32_t R0;
    uint32_t R1;
    uint32_t R2;
    uint32_t R3;
    uint32_t R4;
    uint32_t LR;
    uint32_t PC;
    uint32_t SP;
} sc_reg_save_t;

//////////////////////////////////////////////////////////////////////////////
  
typedef void (*sc_lib_init)(void *h, const char *path);
typedef void (*sc_lib_deinit)(void *h);

//////////////////////////////////////////////////////////////////////////////

typedef void *sc_t;

sc_t sc_alloc(
        uint32_t extra);

void sc_free(
        sc_t sc);

const uint32_t *sc_get(
        const sc_t sc);

uint32_t sc_get_size(
        const sc_t sc);

sc_ctx_t *sc_get_ctx(
        const sc_t sc);

sc_reg_save_t *sc_get_reg_save(
        const sc_t sc);

//////////////////////////////////////////////////////////////////////////////
