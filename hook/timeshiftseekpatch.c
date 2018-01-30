/* 
 *  bugficks
 *	(c) 2013
 *
 *  sectroyer
 *	(c) 2015
 * 
 *  License: GPLv3
 *
 */
//////////////////////////////////////////////////////////////////////////////
//

#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/time.h>   
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <memory.h>
#include <glob.h>
#include <stdarg.h>
#include <pthread.h>
#include <execinfo.h>
#include "common.h"
//#include "dynlib.h"
#include "hook.h"

//#include "structures.h"

//////////////////////////////////////////////////////////////////////////////

#define LIB_NAME "TimeShiftSeekPatch"
#define LIB_VERSION "v0.2.6"
#define LIB_TV_MODELS "H"
#define LIB_PREFIX timeshift
#define LIB_HOOKS LIB_PREFIX##_hooks
#define hCTX LIB_PREFIX##_hook_ctx

#include "util.h"
int addSize=0;

//////////////////////////////////////////////////////////////////////////////
//

typedef union
{
    const void *procs[100];
    struct
    {
        //void *(*new)(unsigned int size);
		unsigned int CMMPSubtitle_Create;

    };
    
} samyGO_whacky_t;

samyGO_whacky_t hCTX = 
{
    (const void*)"_ZN17CMMPSubtitleLabel6CreateEiiiiiiPK6PCTask",
};

#define KEY_UP 2
#define KEY_DOWN 3
#define KEY_LEFT 4
#define KEY_RIGHT 5
#define KEY_OFFSET 20/2

int lastKey=0,left=0,right=0,up=0,down=0;
void handleKeys(unsigned short *event)
{
	if((event[KEY_OFFSET] == KEY_UP) && up)
	{
		logf("Setting KEY_UP to KEY_RIGHT\n","");
		event[KEY_OFFSET]=KEY_RIGHT;
	}
	if((event[KEY_OFFSET] == KEY_DOWN) && down)
	{
		logf("Setting KEY_DOWN to KEY_LEFT\n","");
		event[KEY_OFFSET]=KEY_LEFT;
	}
}
_HOOK_IMPL(int,CPVRTSMgrNormal_KeyProcedure,void *this, unsigned short *event)
{
	lastKey=event[KEY_OFFSET];
	logh("Key: %d\n",lastKey);
	handleKeys(event);
    _HOOK_DISPATCH(CPVRTSMgrNormal_KeyProcedure, this, event);
    return (int)h_ret;
}
_HOOK_IMPL(int,CPVRTSMgrPast_KeyProcedure,void *this, unsigned short *event)
{
	lastKey=event[KEY_OFFSET];
	logh("Key: %d\n",lastKey);
	handleKeys(event);
    _HOOK_DISPATCH(CPVRTSMgrPast_KeyProcedure, this, event);
    return (int)h_ret;
}
_HOOK_IMPL(int,CPETransaction_PlaySkip,void *this, int tmp, int tmp2, int seek, int someBool)
{
	logh("Key: %d, seek: %d\n",lastKey,seek);
	if((lastKey == KEY_UP) && up)
		seek=up*1000;
	if((lastKey == KEY_DOWN) && down)
		seek=down*1000;
	if((lastKey == KEY_LEFT) && left)
		seek=left*1000;
	if((lastKey == KEY_RIGHT) && right)
		seek=right*1000;
    _HOOK_DISPATCH(CPETransaction_PlaySkip, this, tmp, tmp2, seek, someBool);
    return (int)h_ret;
}

//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////


STATIC dyn_fn_t dyn_hook_fn_tab[] =
{
	{ 0, "_ZN15CPVRTSMgrNormal13Key_ProcedureEPK7PTEvent" },
	{ 0, "_ZN13CPVRTSMgrPast13Key_ProcedureEPK7PTEvent" },
	{ 0, "_ZN14CPETransaction8PlaySkipEiRKN10IPVREngine13ePlaySkipTypeEib" },
//	{ 0, "_ZN14CMMSubTitleWnd17t_GetSubtitleSizeEv" },
};

STATIC hook_entry_t LIB_HOOKS[] =
{
#define _HOOK_ENTRY(F, I) \
    &hook_##F, &dyn_hook_fn_tab[I], &x_##F

    { _HOOK_ENTRY(CPVRTSMgrNormal_KeyProcedure, __COUNTER__) },
    { _HOOK_ENTRY(CPVRTSMgrPast_KeyProcedure, __COUNTER__) },
    { _HOOK_ENTRY(CPETransaction_PlaySkip, __COUNTER__) },
 //   { _HOOK_ENTRY(CMM_GetSubtitleSize, __COUNTER__) },


#undef _HOOK_ENTRY
};

#define CMP_R2_0	0xE3520000
#define CMP_R2_1	0xE3520001


//////////////////////////////////////////////////////////////////////////////
static int _hooked = 0;

EXTERN_C void lib_init(
        void *_h, const char *libpath)
{
	unsigned long *cur_addr;
	char *argv[100],*optstr;
    char cfgpath[PATH_MAX];
	int argc; 
    if(_hooked)
    {
        log("Injecting once is enough!\n");
        return;
    }

    //unlink(LOG_FILE);

	log("SamyGO "LIB_TV_MODELS" lib"LIB_NAME" "LIB_VERSION" - (c) sectroyer 2015\n");

	//log("Library path: %s\n",libpath);
    //log("NoDRM dlopen: 0x%08x\n", dlopen(libpath, RTLD_LAZY|RTLD_GLOBAL));
    argc = getArgCArgV(libpath, argv); 
    // realpath doenst work on D 
    // realpath(libpath, cfgpath);

	optstr=getOptArg(argv,argc,"LEFT:");
	if(optstr && strlen(optstr))
	{
		left=atoi(optstr);
		logf("Setting left seek to: %d\n",left);
	}
	optstr=getOptArg(argv,argc,"RIGHT:");
	if(optstr && strlen(optstr))
	{
		right=atoi(optstr);
		logf("Setting right seek to: %d\n",right);
	}
	optstr=getOptArg(argv,argc,"UP:");
	if(optstr && strlen(optstr))
	{
		up=atoi(optstr);
		logf("Setting up seek to: %d\n",up);
	}
	optstr=getOptArg(argv,argc,"DOWN:");
	if(optstr && strlen(optstr))
	{
		down=atoi(optstr);
		logf("Setting down seek to: %d\n",down);
	}

    void *h = dlopen(0, RTLD_LAZY);
    if(!h)
    {
        char *serr = dlerror();
        log("dlopen error %s\n", serr);
        return;
    }
    
    patch_adbg_CheckSystem(h);
    
    //samyGO_whacky_t_init(h, &hCTX, ARRAYSIZE(hCTX.procs));
    //samyGO_whacky_t_init(h, &PCWString, ARRAYSIZE(PCWString.procs));
    
    if(dyn_sym_tab_init(h, dyn_hook_fn_tab, ARRAYSIZE(dyn_hook_fn_tab)) >= 0)
    {
        set_hooks(LIB_HOOKS, ARRAYSIZE(LIB_HOOKS));
        _hooked = 1;
    }
  

    log("init done...\n");
    dlclose(h);
}

EXTERN_C void lib_deinit(
        void *_h)
{
    log(">>> %s\n", __func__); 

    log("If you see this message you forget to specify -r when invoking hijack :)\n"); 

    if(_hooked)
        remove_hooks(LIB_HOOKS, ARRAYSIZE(LIB_HOOKS));

    log("<<< %s\n", __func__); 
}

//////////////////////////////////////////////////////////////////////////////
