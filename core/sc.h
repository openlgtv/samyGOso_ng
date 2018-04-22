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
#include "config.h"

//////////////////////////////////////////////////////////////////////////////

typedef struct {
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

typedef struct {
    size_t len;
    uint8_t *data;
} sc_t;

// gets offset from the start of the .sc section
#define SC_OFFSET(x) ((uintptr_t)&x - (uintptr_t)&_START_OF_SHELL_CODE)

//////////////////////////////////////////////////////////////////////////////

typedef struct
{
#if defined(TARGET_ARM) || defined(TARGET_THUMB)
        uint32_t R0;
        uint32_t R1;
        uint32_t R2;
        uint32_t R3;
        uint32_t R4;
        uint32_t R5;
        uint32_t R6;
        uint32_t R7;
        uint32_t R8;
        uint32_t R9;
        uint32_t R10;
        uint32_t FP;
        uint32_t IP;
        uint32_t LR;
        uint32_t PC;
        uint32_t SP;
#elif defined(TARGET_AMD64)
        uint64_t RAX;
        uint64_t RBX;
        uint64_t RCX;
        uint64_t RDX;
        uint64_t RDI;
        uint64_t RSI;
        uint64_t RBP;
        uint64_t RIP;
        uint64_t R8;
        uint64_t R9;
        uint64_t R10;
        uint64_t R11;
        uint64_t R12;
        uint64_t R13;
        uint64_t R14;
        uint64_t R15;
#endif
} sc_reg_save_t;

//////////////////////////////////////////////////////////////////////////////
  
typedef void (*sc_lib_init)(void *h, const char *path);
typedef void (*sc_lib_deinit)(void *h);

//////////////////////////////////////////////////////////////////////////////

// From C
extern void _SC_FINALIZE(sc_ctx_t *ctx);
// From Assembly
extern void _SHELL_CODE_MAIN(void);
// From LD Script
extern uintptr_t _START_OF_SHELL_CODE;
extern uintptr_t _END_OF_SHELL_CODE;

#ifdef TARGET_AMD64
extern uintptr_t _SC_STACK;
#endif

extern sc_ctx_t _SHELL_CODE_CTX;
extern unsigned int _SHELL_CODE_REG_SAVE[]; 

sc_t *sc_alloc(uint32_t extra);
void sc_free(sc_t *sc);
const uint8_t *sc_get(const sc_t *sc);
uint32_t sc_get_size(const sc_t *sc);
sc_ctx_t *sc_get_ctx(const sc_t *sc);
sc_reg_save_t *sc_get_reg_save(const sc_t *sc);

//////////////////////////////////////////////////////////////////////////////
