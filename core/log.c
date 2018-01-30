#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>

static FILE *logHandle = NULL;
FILE *log_init(const char *logPath){
    if(logHandle != NULL)
        fclose(logHandle);
        
    logHandle = fopen(logPath, "a+");
    return logHandle;
}

void mprintf(const char *fmt, ...){
    va_list ap;
    if(!logHandle)
        return;
    
    va_start(ap, fmt);
    vfprintf(logHandle, fmt, ap);
    va_end(ap);

    fflush(logHandle);
}
void vmprintf(const char * restrict fmt, va_list ap){
    if(!logHandle)
        return;
    
    vfprintf(logHandle, fmt, ap);
    fflush(logHandle);
}