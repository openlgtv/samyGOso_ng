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

#include <malloc.h>
#include <memory.h>
#include "sc.h"
#include "common.h"

//////////////////////////////////////////////////////////////////////////////

#define SC_SECTION  ".sc"
#define SC_DECL     DECL_SPEC(section(SC_SECTION))

//////////////////////////////////////////////////////////////////////////////

void SC_DECL _SC_FINALIZE(sc_ctx_t *ctx)
{  
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
}

//////////////////////////////////////////////////////////////////////////////

static inline size_t sc_get_size_raw() {
    return SC_OFFSET(_START_OF_SHELL_CODE);
}

//////////////////////////////////////////////////////////////////////////////

sc_t *sc_alloc(uint32_t extra){
    int size_raw = sc_get_size_raw();
    
    int nalloc = size_raw + extra;
    sc_t *sc = calloc(1, sizeof(sc_t));
    sc->len = nalloc;
    sc->data = calloc(1, nalloc);

    memcpy(sc->data, (void *)&_START_OF_SHELL_CODE, size_raw);
    return sc;
}

void sc_free(sc_t *sc){
    free(sc->data);
    free(sc);
}

const uint8_t *sc_get(const sc_t *sc){
    return sc->data;
}

uint32_t sc_get_size(const sc_t *sc){
    return sc->len;
}

sc_ctx_t *sc_get_ctx(const sc_t *sc){
    return (sc_ctx_t *)(sc->data + SC_OFFSET(_SHELL_CODE_CTX));
}

sc_reg_save_t *sc_get_reg_save(const sc_t *sc){
    return (sc_reg_save_t *)(sc->data + SC_OFFSET(_SHELL_CODE_REG_SAVE));
}

//////////////////////////////////////////////////////////////////////////////
