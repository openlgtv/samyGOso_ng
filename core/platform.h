#ifndef __PLATFORM_H
#define __PLATFORM_H

#include <stdint.h>

typedef struct {
	void (*find_name)(pid_t pid, const char *name, void **address);	
};