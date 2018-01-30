#ifndef __MLOG_H
#define __MLOG_H
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include "common.h"

EXTERN_C_BEGIN

FILE *log_init(const char *logPath);
void vmprintf(const char * restrict fmt, va_list ap);
void mprintf(const char *fmt, ...);

#define print(fmt,...) mprintf("[%s] "fmt, __func__, ##__VA_ARGS__)

EXTERN_C_END
#endif