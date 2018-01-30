#ifndef __HOOK_H__
#define __HOOK_H__

#include <stdint.h>
#include "common.h"
#include "config.h"

#if defined(TARGET_ARM)
// ldr pc, [pc, #0]     00 F0 9F E5
//.long addr            00 00 00 00
//.long addr            00 00 00 00
#define HIJACK_SIZE 12
inline uint8_t *getHCode(uintptr_t _new){
        uint8_t *n_code = "\x00\xf0\x9f\xe5\x00\x00\x00\x00\x00\x00\x00\x00";
        *(uintptr_t *)&n_code[4] = _new;
        *(uintptr_t *)&n_code[8] = _new;
        return n_code;
}
#elif defined(TARGET_THUMB)
// add r0, pc, #4       01 A0
// ldr r0, [r0, #0]     00 68
// mov pc, r0           87 46
// mov pc, r0           87 46
// .long addr           00 00 00 00
#define HIJACK_SIZE 12
inline uint8_t *getCode(uintptr_t _new){
        uint8_t *n_code = "\x01\xa0\x00\x68\x87\x46\x87\x46\x00\x00\x00\x00";
        *(uintptr_t *)&n_code[8] = (uintptr_t)_new;
        //TODO: decrement target (_new)
        return n_code;
}
#elif defined(TARGET_I386)
#elif defined(TARGET_AMD64)
// push $XXXXXXXX        68 XX XX XX XX
// mov 4(%rsp), XXXXXXXX C7 44 24 04 XX XX XX XX
// retq                  C3
#define HIJACK_SIZE 14
inline uint8_t *getCode(uintptr_t _new){
        uint8_t *n_code = "\x68\x00\x00\x00\x00xc7\x44\x24\x04\x00\x00\x00\x00\xc3";
        *(uint32_t *)&n_code[1] = (uint32_t)_new; // low
        *(uint32_t *)&n_code[9] = (uint32_t)(_new >> 32); //high
        return n_code;
}
#else
#error "Unsupported Target"
#endif

typedef struct
{
    void *addr;
    uint8_t o_code[HIJACK_SIZE];
    uint8_t n_code[HIJACK_SIZE];
} sym_hook_t;


EXTERN_C_BEGIN

void hijack_start(sym_hook_t *sa, void *target, void *_new);
void hijack_pause(sym_hook_t *sa);
void hijack_resume(sym_hook_t *sa);
void hijack_stop(sym_hook_t *sa);

EXTERN_C_END

#endif //__HOOK_H__
