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

#include "sc.h"
#include "common.h"
#include <malloc.h>
#include <memory.h>

//////////////////////////////////////////////////////////////////////////////

#define SC_SECTION  ".sc"
#define SC_DECL     DECL_SPEC(section(SC_SECTION), naked, noinline)

//////////////////////////////////////////////////////////////////////////////

typedef struct
{
    uint32_t len;
    uint32_t *data;
} _sc_t;

//////////////////////////////////////////////////////////////////////////////

static void SC_DECL _SHELL_CODE()
{
    register sc_ctx_t *ctx __asm__("r0");

    asm volatile
    (
        "ADR        R0, L_sc_ctx_t;"
    );
     
    ctx->lib = ctx->dlopen(ctx->lib_name, RTLD_LAZY);
    if(ctx->lib)
    {
        ctx->fn_init = ctx->dlsym(ctx->lib, ctx->lib_init);
        ctx->fn_deinit = ctx->dlsym(ctx->lib, ctx->lib_deinit);

        if(ctx->fn_init)
            ((sc_lib_init)ctx->fn_init)(ctx->lib, ctx->lib_name);
        
        if(ctx->dlclose)
        {
            if(ctx->fn_deinit)
                ((sc_lib_deinit)ctx->fn_deinit)(ctx->lib);
            ctx->dlclose(ctx->lib);
        }
    }
    
    asm volatile
    (
        "LDR        SP, L_SP;"
        "LDR        R0, L_R0;"
        "LDR        R1, L_R1;"
        "LDR        R2, L_R2;"
        "LDR        R3, L_R3;"
        "LDR        R4, L_R4;"
        "LDR        LR, L_LR;"
        "LDR        PC, L_PC;"
    );
    //_SHELL_CODE_REG_SAVE
    //_SHELL_CODE_CTX
}

static void SC_DECL _SHELL_CODE_REG_SAVE()
{
    asm volatile
    (
    "L_sc_reg_save_t:   ;"
        "L_R0:          .word 0xe1a00000;"
        "L_R1:          .word 0xe1a00001;"
        "L_R2:          .word 0xe1a00002;"
        "L_R3:          .word 0xe1a00003;"
        "L_R4:          .word 0xe1a00004;"
        "L_LR:          .word 0xe1a00005;"
        "L_PC:          .word 0xe1a00006;"
        "L_SP:          .word 0xe1a00007;"
     );
}

static void SC_DECL _SHELL_CODE_CTX()
{
    asm volatile
    (
    "L_sc_ctx_t:        ;"
        "L_dlopen:      .word 0xe1a00008;"
        "L_dlsym:       .word 0xe1a00009;"
        "L_dlclose:     .word 0xe1a0000A;"
        ".lib:          .word 0;"
        ".fn_init:      .word 0;"
        ".fn_deinit:    .word 0;"
        "L_lib_init:    .fill 16, 1, 0;"
        "L_lib_deinit:  .fill 16, 1, 0;"
        "L_soname:      ;"
    );
}

static void SC_DECL _END_OF_SHELL_CODE()
{
}

//////////////////////////////////////////////////////////////////////////////

static uint32_t sc_get_size_raw()
{
    return (uintptr_t)_END_OF_SHELL_CODE - (uintptr_t)_SHELL_CODE;
}

//////////////////////////////////////////////////////////////////////////////

sc_t sc_alloc(uint32_t extra){
    int nalloc = sc_get_size_raw() + extra;
    _sc_t *sc = malloc(sizeof(sc_t));
    sc->len = nalloc;
    sc->data = (uint32_t*)malloc(nalloc);
    memset(sc->data, 0, nalloc);
    memcpy(sc->data, _SHELL_CODE, sc_get_size_raw());
    
    return (sc_t*)sc;
}

void sc_free(
        sc_t sc)
{
    free(((_sc_t*)sc)->data);
    free((_sc_t*)sc);
}

const uint32_t *sc_get(
        const sc_t sc)
{
    return ((_sc_t*)sc)->data;
}

uint32_t sc_get_size(
        const sc_t sc)
{
    return ((_sc_t*)sc)->len;
}

sc_ctx_t *sc_get_ctx(
        const sc_t sc)
{
    int offs = (uintptr_t)_SHELL_CODE_CTX - (uintptr_t)_SHELL_CODE;
    
    return (sc_ctx_t*)((uint8_t*)((_sc_t*)sc)->data + offs);
}

sc_reg_save_t *sc_get_reg_save(
        const sc_t sc)
{
    int offs = (uintptr_t)_SHELL_CODE_REG_SAVE - (uintptr_t)_SHELL_CODE;

    return (sc_reg_save_t*)((uint8_t*)((_sc_t*)sc)->data + offs);
}

//////////////////////////////////////////////////////////////////////////////
