/* 
 * hijack.c - force a process to load a library
 *
 *  sectroyer
 *	(c) 2014
 *  added support for custom and standard process names
 *  fixed a bug with injecting non-existent libs
 *
 *
 *  modified to work on samsung F* series by:
 *  bugficks
 *	(c) 2013
 *
 *  completely rewritten shellcode
 *  json config support
 *  + other minor stuff :)
 *
 *  ARM / Android version by:
 *  Collin Mulliner <collin[at]mulliner.org>
 *  http://www.mulliner.org/android/
 *	(c) 2012
 *
 *
 *  original x86 version by:
 *  Copyright (C) 2002 Victor Zandy <zandy[at]cs.wisc.edu>
 *
 *  License: LGPL 2.1
 *
 */
 
#define _XOPEN_SOURCE 500  /* include pread,pwrite */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <elf.h>
#include <unistd.h>
#include <errno.h>       
#include <sys/mman.h>
#include <sys/user.h>
#include "sc.h"
#include "sys/queue.h"
#include "nxjson/nxjson.h"
#include "elf_types.h"
#include <dirent.h>

#include "config.h"

#define EXTRA_COOKIE    0x82374021
#define MAX_ARGCV_LEN   1024

int _argc;
const char **_argv;

int debug = 0;
unsigned int stack_start;
unsigned int stack_end;
static unsigned char addlibcaddr = 0;
/* memory map for libraries */
#define MAX_NAME_LEN 256
#define MEMORY_ONLY  "[memory]"
struct mm {
	char name[MAX_NAME_LEN];
	unsigned long start, end;
};

typedef struct symtab *symtab_t;
struct symlist {
	Elf_Sym *sym;       /* symbols */
	char *str;            /* symbol strings */
	unsigned num;         /* number of symbols */
};
struct symtab {
	struct symlist *st;    /* "static" symbols */
	struct symlist *dyn;   /* dynamic symbols */
};

/**
 * malloc wrapper
 */
static void *
xmalloc(size_t size)
{
	void *p = malloc(size);
	if (!p) {
		printf("Out of memory\n");
		exit(1);
	}
	return p;
}

/**
 * Extracts symbols from a section
 */ 
static struct symlist *
get_syms(int fd, Elf_Shdr *symh, Elf_Shdr *strh)
{
	struct symlist *sl, *ret;
	int rv;

	ret = NULL;
	sl = (struct symlist *) xmalloc(sizeof(struct symlist));
	sl->str = NULL;
	sl->sym = NULL;

	/* sanity */
	if (symh->sh_size % sizeof(Elf_Sym)) { 
		printf("elf_error\n");
		goto out;
	}

	/* symbol table */
	sl->num = symh->sh_size / sizeof(Elf_Sym);
	sl->sym = (Elf_Sym *) xmalloc(symh->sh_size);
	rv = pread(fd, sl->sym, symh->sh_size, symh->sh_offset);
	if (rv <= 0) {
		perror("read");
		goto out;
	}
	if (symh->sh_size != rv) {
		printf("elf error in symbol table\n");
		goto out;
	}

	/* string table */
	sl->str = (char *) xmalloc(strh->sh_size);
	rv = pread(fd, sl->str, strh->sh_size, strh->sh_offset);
	if (rv <= 0) {
		//perror("read");
		goto out;
	}
	if (strh->sh_size != rv) {
		printf("elf error in string table\n");
		goto out;
	}

	ret = sl;
out:
	return ret;
}

/**
 * Processes the opened file and retrives its symbols
 */
static int
do_load(int fd, symtab_t symtab)
{
	int rv;
	size_t size;
	Elf_Ehdr ehdr;
	Elf_Shdr *shdr = NULL, *p;
	Elf_Shdr *dynsymh, *dynstrh;
	Elf_Shdr *symh, *strh;
	char *shstrtab = NULL;
	int i;
	int ret = -1;
	
	/* elf header */
	rv = read(fd, &ehdr, sizeof(ehdr));
	if (rv <= 0) {
		//perror("read");
		goto out;
	}
	if (rv != sizeof(ehdr)) {
		printf("elf error in header\n");
		goto out;
	}
	if (strncmp(ELFMAG, ehdr.e_ident, SELFMAG)) { /* sanity */
		printf("not an elf\n");
		goto out;
	}
	if (sizeof(Elf_Shdr) != ehdr.e_shentsize) { /* sanity */
		printf("elf error in elf size\n");
		goto out;
	}

	/* section header table */
	size = ehdr.e_shentsize * ehdr.e_shnum;
	shdr = (Elf_Shdr *) xmalloc(size);
	rv = pread(fd, shdr, size, ehdr.e_shoff);
	if (rv <= 0) {
		//perror("read");
		goto out;
	}
	if (rv != size) {
		printf("elf error in section header\n");
		goto out;
	}
	
	/* section header string table */
	size = shdr[ehdr.e_shstrndx].sh_size;
	shstrtab = (char *) xmalloc(size);
	rv = pread(fd, shstrtab, size, shdr[ehdr.e_shstrndx].sh_offset);
	if (rv <= 0) {
		//perror("read");
		goto out;
	}
	if (rv != size) {
		printf("elf error in string table header\n");
		goto out;
	}

	/* symbol table headers */
	symh = dynsymh = NULL;
	strh = dynstrh = NULL;
	for (i = 0, p = shdr; i < ehdr.e_shnum; i++, p++)
		if (SHT_SYMTAB == p->sh_type) {
			if (symh) {
				printf("too many symbol tables\n");
				goto out;
			}
			symh = p;
		} else if (SHT_DYNSYM == p->sh_type) {
			if (dynsymh) {
				printf("too many symbol tables\n");
				goto out;
			}
			dynsymh = p;
		} else if (SHT_STRTAB == p->sh_type
			   && !strncmp(shstrtab+p->sh_name, ".strtab", 7)) {
			if (strh) {
				printf("too many string tables\n");
				goto out;
			}
			strh = p;
		} else if (SHT_STRTAB == p->sh_type
			   && !strncmp(shstrtab+p->sh_name, ".dynstr", 7)) {
			if (dynstrh) {
				printf("too many string tables\n");
				goto out;
			}
			dynstrh = p;
		}
	/* sanity checks */
	if ((!dynsymh && dynstrh) || (dynsymh && !dynstrh)) {
		printf("bad dynamic symbol table");
		goto out;
	}
	if ((!symh && strh) || (symh && !strh)) {
		printf("bad symbol table");
		goto out;
	}
	if (!dynsymh && !symh) {
		printf("no symbol table");
		goto out;
	}

	/* symbol tables */
	if (dynsymh)
		symtab->dyn = get_syms(fd, dynsymh, dynstrh);
	if (symh)
		symtab->st = get_syms(fd, symh, strh);
	ret = 0;
out:
	free(shstrtab);
	free(shdr);
	return ret;
}

/**
 * Retrives the symbols from a given ELF file
 */
static symtab_t
load_symtab(char *filename)
{
	int fd;
	symtab_t symtab;

	symtab = (symtab_t) xmalloc(sizeof(*symtab));
	memset(symtab, 0, sizeof(*symtab));

	fd = open(filename, O_RDONLY);
	if (fd <= 0) {
		//perror("open");
		return NULL;
	}
	if (do_load(fd, symtab) < 0) {
		printf("Error ELF parsing %s\n", filename);
		free(symtab);
		symtab = NULL;
	}
	close(fd);
	return symtab;
}


/**
 * Loads the /proc/<pid>/maps for a given pid and prepares a list of loaded libraries
 */ 
static int
load_memmap(pid_t pid, struct mm *mm, int *nmmp)
{
	static char raw[640000]; // this depends on the number of libraries an executable uses
	char name[MAX_NAME_LEN];
	char *p;
	unsigned long start, end;
	struct mm *m;
	int nmm = 0;
	int fd, rv;
	int i;

	sprintf(raw, "/proc/%d/maps", pid);
	fd = open(raw, O_RDONLY);
	if (0 > fd) {
		printf("Can't open %s for reading\n", raw);
		return -1;
	}

	/* Zero to ensure data is null terminated */
	memset(raw, 0, sizeof(raw));

	p = raw;
	while (1) {
		rv = read(fd, p, sizeof(raw)-(p-raw));
		if (rv < 0) {
			perror("read");
			return -1;
		}
		if (rv == 0)
			break;
		p += rv;
		if (p-raw >= sizeof(raw)) {
			printf("Too many memory mappings\n");
			return -1;
		}
	}
	close(fd);

	p = strtok(raw, "\n");
	m = mm;

	while (p) {
		/* parse current map line */
		rv = sscanf(p, "%x-%x %*s %*s %*s %*s %s\n",
			    &start, &end, name);

		p = strtok(NULL, "\n");

		if (rv == 2) {
			m = &mm[nmm++];
			m->start = start;
			m->end = end;
			strcpy(m->name, MEMORY_ONLY);
			continue;
		}

		if (strstr(name, "stack") != 0) {
			stack_start = start;
			stack_end = end;
		}

		/* search backward for other mapping with same name */
		for (i = nmm-1; i >= 0; i--) {
			m = &mm[i];
			if (!strcmp(m->name, name))
				break;
		}

		if (i >= 0) {
			if (start < m->start)
				m->start = start;
			if (end > m->end)
				m->end = end;
		} else {
			/* new entry */
			m = &mm[nmm++];
			m->start = start;
			m->end = end;
			strcpy(m->name, name);
		}
	}

	*nmmp = nmm;
	return 0;
}

/**
 * Find libc in MM, storing no more than LEN-1 chars of
 * its name in NAME and set START to its starting
 * address.  If libc cannot be found return -1 and
 * leave NAME and START untouched.  Otherwise return 0
 * and null-terminated NAME.
 */
static int
find_libc(char *name, int len, unsigned long *start,
	  struct mm *mm, int nmm)
{
	int i;
	struct mm *m;
	char *p;
	for (i = 0, m = mm; i < nmm; i++, m++) {
		if (!strcmp(m->name, MEMORY_ONLY))
			continue;
		p = strrchr(m->name, '/');
		if (!p)
			continue;
		p++;
		if (strncmp("libc", p, 4))
			continue;
		p += 4;

		/* here comes our crude test -> 'libc.so' or 'libc-[0-9]' */
		if (!strncmp(".so", p, 3) || (p[0] == '-' && isdigit(p[1])))
			break;
	}
	if (i >= nmm)
		/* not found */
		return -1;

	*start = m->start;
	strncpy(name, m->name, len);
	if (strlen(m->name) >= len)
		name[len-1] = '\0';
	return 0;
}

static int
find_linker_mem(char *name, int len, unsigned long *start,
	  struct mm *mm, int nmm)
{
	int i;
	struct mm *m;
	char *p;
	for (i = 0, m = mm; i < nmm; i++, m++) {
		//printf("name = %s\n", m->name);
		//printf("start = %x\n", m->start);
		if (!strcmp(m->name, MEMORY_ONLY))
			continue;
		p = strrchr(m->name, '/');
		if (!p)
			continue;
		p++;
		if (strstr("libdl", p) != NULL)
			continue;
		
		p += 4;
		/* here comes our crude test -> 'libc.so' or 'libc-[0-9]' */
		if (!strncmp(".so", p, 3) || (p[0] == '-' && isdigit(p[1])))
			break;
	}
	if (i >= nmm)
		/* not found */
		return -1;

	*start = m->start;
	strncpy(name, m->name, len);
	if (strlen(m->name) >= len)
		name[len-1] = '\0';
	return 0;
}

static int
lookup2(
	struct symlist *sl, unsigned char type,
	char *name, uintptr_t *val
){
	Elf_Sym *p;
	int len;
	int i;

	len = strlen(name);
	for (i = 0, p = sl->sym; i < sl->num; i++, p++) {
		//printf("name: %s %x\n", sl->str+p->st_name, p->st_value);
		if (!strncmp(sl->str+p->st_name, name, len)
		    && ELF_ST_TYPE(p->st_info) == type) {
			//if (p->st_value != 0) {
			*val = p->st_value;
			return 0;
			//}
		}
	}
	return -1;
}

static int
lookup_sym(
	symtab_t s, unsigned char type,
	char *name, uintptr_t *val
){
	if (s->dyn && !lookup2(s->dyn, type, name, val))
		return 0;
	if (s->st && !lookup2(s->st, type, name, val))
		return 0;
	return -1;
}

static int
lookup_func_sym(symtab_t s, char *name, uintptr_t *val)
{
	return lookup_sym(s, STT_FUNC, name, val);
}

static int
find_name(pid_t pid, char *name, uintptr_t *addr)
{
	struct mm mm[16000];
	unsigned long libcaddr;
	int nmm;
	char libc[256];
	symtab_t s;

	if (load_memmap(pid, mm, &nmm) < 0) {
		printf("cannot read memory map\n");
		return -1;
	}
	if (find_libc(libc, sizeof(libc), &libcaddr, mm, nmm) < 0) {
		printf("cannot find libc\n");
		return -1;
	}
	s = load_symtab(libc);
	if (!s) {
		printf("cannot read symbol table\n");
		return -1;
	}
	if (lookup_func_sym(s, name, addr) < 0) {
		printf("cannot find %s\n", name);
		return -1;
	}
	if ( (*addr & 0xFF000000) != (libcaddr & 0xff000000) ) {
		//if (addlibcaddr == 1)
		printf("adding libc addr to found symaddress %08X + %08X => %08X\n", *addr, libcaddr, (*addr + libcaddr) );
		*addr = (*addr + libcaddr);
	}
	return 0;
}

static int find_linker(pid_t pid, uintptr_t *addr)
{
	struct mm mm[16000];
	unsigned long libcaddr;
	int nmm;
	char libc[256];
	symtab_t s;

	if (load_memmap(pid, mm, &nmm) < 0) {
		printf("cannot read memory map\n");
		return -1;
	}
	if (find_linker_mem(libc, sizeof(libc), &libcaddr, mm, nmm) < 0) {
		printf("cannot find linker\n");
		return -1;
	}
	
	*addr = libcaddr;
	
	return 1;
}

/* Write NLONG 4 byte words from BUF into PID starting
   at address POS.  Calling process must be attached to PID. */
static int
write_mem(pid_t pid, unsigned long *buf, int nlong, unsigned long pos)
{
	unsigned long *p;
	int i;

	for (p = buf, i = 0; i < nlong; p++, i++)
		if (0 > ptrace(PTRACE_POKETEXT, pid, pos+(i*4), *p))
			return -1;
	return 0;
}

static int
read_mem(pid_t pid, unsigned long *buf, int nlong, unsigned long pos)
{
	unsigned long *p;
	int i;

	for (p = buf, i = 0; i < nlong; p++, i++)
		if ((*p = ptrace(PTRACE_PEEKTEXT, pid, pos+(i*4), *p)) < 0)
			return -1;
	return 0;
}

struct pt_regs2 {
         long uregs[18];
};

#define ARM_cpsr        uregs[16]
#define ARM_pc          uregs[15]
#define ARM_lr          uregs[14]
#define ARM_sp          uregs[13]
#define ARM_ip          uregs[12]
#define ARM_fp          uregs[11]
#define ARM_r10         uregs[10]
#define ARM_r9          uregs[9]
#define ARM_r8          uregs[8]
#define ARM_r7          uregs[7]
#define ARM_r6          uregs[6]
#define ARM_r5          uregs[5]
#define ARM_r4          uregs[4]
#define ARM_r3          uregs[3]
#define ARM_r2          uregs[2]
#define ARM_r1          uregs[1]
#define ARM_r0          uregs[0]
#define ARM_ORIG_r0     uregs[17]


typedef struct hijack_cfg_entries
{
    char path[PATH_MAX];
    uint8_t keep;
    char init[16];
    char deinit[16];
    STAILQ_ENTRY(hijack_cfg_entries) entries;
} hijack_cfg_entry_t;

static STAILQ_HEAD(slisthead, hijack_cfg_entries) hijack_cfg = STAILQ_HEAD_INITIALIZER(hijack_cfg);


static int load_config(
        const char *cfgfile)
{
    if(!cfgfile)
    {
        return -1;
    }
    FILE *f = fopen(cfgfile, "r");
    if(!f)
    {
        return -2;
    }

    fseek(f, 0L, SEEK_END);
    long cfgsize = ftell(f); 
    if(!cfgsize)
    {
        fclose(f);
        return -3;
    }
    fseek(f, 0, SEEK_SET);

    const char nxjs_fix_s[] = "{\".\":";
    const char nxjs_fix_e[] = "}";
    long allocsize = cfgsize + sizeof(nxjs_fix_s) + sizeof(nxjs_fix_e) - 2;
    
    char *cfgdata = malloc(allocsize);
    const nx_json *cfgjson = 0;
    if(cfgdata)
    {
        strcpy(cfgdata, nxjs_fix_s);
        fread(cfgdata + sizeof(nxjs_fix_s) - 1, 1, cfgsize, f);
        cfgdata[allocsize - 1] = '}';
        cfgdata[allocsize] = 0;
        cfgjson = nx_json_parse_utf8(cfgdata);
    }

    free(cfgdata);
    fclose(f);

    if(!cfgjson || !cfgjson->child)
    {
        return -4;
    }
    
    int cfg_entry_cnt = 0;
    const nx_json *_cfgjson = cfgjson;
    cfgjson = cfgjson->child;
    int jscfg_so_cnt = cfgjson->length;
    for(int i = 0; i < jscfg_so_cnt; i++)
    {
        const nx_json *jscfg_so = nx_json_item(cfgjson, i);

        const nx_json *iter = 0;
        if(jscfg_so)
            iter = jscfg_so->child;
        
        hijack_cfg_entry_t *cfg_entry = malloc(sizeof(hijack_cfg_entry_t));
        memset(cfg_entry, 0, sizeof(hijack_cfg_entry_t));
        
        while(iter)
        {
            if(strncmp(iter->key, "keep", 4) == 0)
            {
                //printf("keep: %d\n", iter->int_value);
                cfg_entry->keep = iter->int_value;
            }
            else if(strncmp(iter->key, "path", 4) == 0)
            {
                //printf("path: %s\n", iter->text_value);
                strncpy(cfg_entry->path, iter->text_value, sizeof(cfg_entry->path));
            }
            else if(strncmp(iter->key, "init", 4) == 0)
            {
                //printf("init: %s\n", iter->text_value);
                strncpy(cfg_entry->init, iter->text_value, sizeof(cfg_entry->init));
            }
            else if(strncmp(iter->key, "deinit", 6) == 0)
            {
                //printf("deinit: %s\n", iter->text_value);
                strncpy(cfg_entry->deinit, iter->text_value, sizeof(cfg_entry->deinit));
            }
            iter = iter->next;
        }

        if(access(cfg_entry->path, F_OK) >= 0)
        {
            STAILQ_INSERT_TAIL(&hijack_cfg, cfg_entry, entries);
            cfg_entry_cnt++;
        }
        else
        {
            //char *ppp = strerror(errno);
            printf("Error accessing .so file '%s' [%s]\n", cfg_entry->path, strerror(errno));
        }
    }

    nx_json_free(_cfgjson);
}

pid_t proc_find(const char* name) 
{
    DIR* dir;
    struct dirent* ent;
    char* endptr;
    char buf[512];

    if (!(dir = opendir("/proc"))) {
        perror("can't open /proc");
        return -1;
    }

    while((ent = readdir(dir)) != NULL) {
        /* if endptr is not a null character, the directory is not
         * entirely numeric, so ignore it */
        long lpid = strtol(ent->d_name, &endptr, 10);
        if (*endptr != '\0') {
            continue;
        }

        /* try to open the cmdline file */
        snprintf(buf, sizeof(buf), "/proc/%ld/cmdline", lpid);
        FILE* fp = fopen(buf, "r");

        if (fp) {
            if (fgets(buf, sizeof(buf), fp) != NULL) {
                /* check the first token in the file, the program name */
                char* first = strtok(buf, " ");
				if(strrchr(first,'/'))
					first=strrchr(first,'/')+1;
                if (!strcmp(first, name)) {
                    fclose(fp);
                    closedir(dir);
                    return (pid_t)lpid;
                }
            }
            fclose(fp);
        }

    }

    closedir(dir);
    return -1;
}

static int inject_lib(pid_t pid, const char *lib_name, int resident);
static int init_extra(int argc, const char *argv[], char **_extra);

static void usage_and_exit(const char *argv[]){
	fprintf(stderr, "usage: %s [-p PID | -n procname | -A | -T | -D ] [-B ] {-c CONFIG | -l /full/path/to/inject.so [-r (=resident)]} [-d (=debug on)] [-a (=add libc addressoffset )] [arg0,...,argN]\n", argv[0]);
	exit(0);
}

int main(int argc, const char *argv[]){
	pid_t pid = 0, backpid = 0;
	int opt = 0;
    int resident = 0;
	char *lib_name = 0;
	const char *config = 0;
	addlibcaddr = 0;

    _argc = argc;
    _argv = argv;

    printf("samyGOso v1.2.5 (c) bugficks 2013-2014, sectroyer 2014-2015, smx 2017\n");
 	
    while ((opt = getopt(argc, argv, "p:c:l:drn:TADB")) != -1) {
		switch (opt) {
			case 'a':
				addlibcaddr = 1;
				break;
			case 'p':
				pid = strtol(optarg, NULL, 0);
			break;
			case 'T':
				pid=proc_find("exeTV");
			break;
			case 'A':
				pid=proc_find("exeAPP");
			break;
			case 'D':
				pid=proc_find("exeDSP");
			break;
			case 'B':
				backpid=proc_find("exeDSP");
			break;
			case 'n':
				//printf("PROC: %s, PID: %d\n",optarg,proc_find(optarg));
				pid=proc_find(optarg);
			break;
			case 'l':
                lib_name = optarg;
				break;
			case 'c':
			    config = optarg;
			    break;
			case 'd':
				debug = 1;
				break;
			case 'r':
				resident = 1;
				break;
			default:
                usage_and_exit(argv);
				break;
		}
	}
	if(backpid > 0)
		pid=backpid;
    if(pid == 0 || pid == -1)
        usage_and_exit(argv);
    if(!lib_name && !config)
        usage_and_exit(argv);
    if(lib_name && config)
        usage_and_exit(argv);

    if(lib_name)
    {
		struct stat statbuf;
		if((stat(lib_name, &statbuf) == -1) || statbuf.st_size == 0)
		{
			fprintf(stderr,"Library \"%s\" doesn't exist!!!\n",lib_name);
			usage_and_exit(argv);
		}
        if(lib_name[0] != '/')
            usage_and_exit(argv);
    
        //char lib_path_buf[PATH_MAX];
        //lib_name = realpath(lib_name, lib_path_buf);

        printf("Injecting '%s' resident: '%d'\n", lib_name, resident);
        if(0 > inject_lib(pid, lib_name, resident))
            printf("Failed.\n");
        else
            printf("Succeeded.\n");
    }
    else if(config)
    {
        load_config(config);
        hijack_cfg_entry_t *cfg_entry = NULL;
        STAILQ_FOREACH(cfg_entry, &hijack_cfg, entries)
        {
        	//char lib_path_buf[PATH_MAX];
            //lib_name = realpath(cfg_entry->path, lib_path_buf);
            lib_name = cfg_entry->path;
            if(lib_name[0] != '/')
            {
                printf("Skipping '%s' - not using absolute path\n", lib_name, cfg_entry->keep);
                continue;
            }

            printf("Injecting '%s' resident: '%d' ", lib_name, cfg_entry->keep);
            if(0 > inject_lib(pid, lib_name, cfg_entry->keep))
                printf("failed.\n");
            else
                printf("succeeded.\n");

        }

        while(!STAILQ_EMPTY(&hijack_cfg))
        {
            hijack_cfg_entry_t *cfg_entry = STAILQ_FIRST(&hijack_cfg);
            STAILQ_REMOVE_HEAD(&hijack_cfg, entries);
            free(cfg_entry);
        }
    }
}

static int init_extra(
	int argc, const char *argv[],
	char **_extra
){
    if(optind <= 0)
        return 0;

    int i;
    int _argc = 0;
    int extra_len = sizeof(EXTRA_COOKIE);
    for(i = optind; i < argc; i++)
    {
        int argcv_len = sizeof(_argc) + sizeof(uintptr_t) * (_argc + 1);
        int l = strlen(argv[i]) + 1;
        if(extra_len + argcv_len + l > MAX_ARGCV_LEN)
            break;

        extra_len += l;
        _argc++;
    }
    
    int argcv_len = sizeof(_argc) + sizeof(uintptr_t) * _argc;
    extra_len += argcv_len;
    extra_len = (extra_len & ~3) + 4;

    char *extra = malloc(extra_len);
    memset(extra, 0, extra_len);
    
    uintptr_t *extra_u32 = (uintptr_t *)extra;
    extra_u32[0] = EXTRA_COOKIE;
    extra_u32[1] = _argc;

    uintptr_t *_argv = &extra_u32[2];
    char *ppp = extra + argcv_len + sizeof(EXTRA_COOKIE);
    for(i = 0; i < _argc; i++)
    {
        _argv[i] = ppp - extra;
        strcpy(ppp, argv[optind + i]);
        ppp += strlen(argv[optind + i]) + 1;
    }

    *_extra = extra;
    return extra_len;
}

typedef struct
{
	uintptr_t dlopenaddr, dlcloseaddr, dlsymaddr, mprotectaddr;
} inject_info_t;

static int inject_prepare(
        pid_t pid, inject_info_t *inject_info)
{
    uintptr_t mprotectaddr = 0;
    uintptr_t dlopenaddr = 0;
    uintptr_t dlcloseaddr = 0;
    uintptr_t dlsymaddr = 0;

    if(find_name(pid, "mprotect", &mprotectaddr) < 0)
    {
		printf("can't find address of mprotect(), error!\n");
		return -1;
	}
	if (debug)
		printf("mprotect: 0x%08X\n", mprotectaddr);

	void *ldl = dlopen("libdl.so.2", RTLD_LAZY);
    if(!ldl)
    {
		printf("dlopen libdl.so.2, error!\n");
		return -1;
	}


    dlopenaddr  = (uintptr_t)dlsym(ldl, "dlopen");
    dlcloseaddr = (uintptr_t)dlsym(ldl, "dlclose");
	dlsymaddr   = (uintptr_t)dlsym(ldl, "dlsym");
	dlclose(ldl);

    if(!dlopenaddr || !dlcloseaddr || !dlsymaddr)
    {
		printf("dlsym libdl.so.2, error!\n");
        return -2;
    }

	uintptr_t this_linker, their_linker;
	if(find_linker(getpid(), &this_linker) < 0)
    {
        printf("find_linker pid: %d, error!\n", getpid());
        return -3;
    }
	//printf("own linker: 0x%x\n", this_linker);
	//printf("offset %x\n", dlopenaddr - this_linker);
	if(find_linker(pid, &their_linker) < 0)
    {
        printf("find_linker pid: %d, error!\n", pid);
        return -4;
    }
	//printf("tgt linker: %x\n", their_linker);
	//printf("tgt dlopen : %x\n", their_linker + (dlopenaddr - this_linker));
	dlopenaddr = their_linker + (dlopenaddr - this_linker);
	dlcloseaddr = their_linker + (dlcloseaddr - this_linker);
	dlsymaddr = their_linker + (dlsymaddr - this_linker);
	if(debug)
	{
    	printf("dlopen   : 0x%08X\n", dlopenaddr);
    	printf("dlclose  : 0x%08X\n", dlcloseaddr);
    	printf("dlsymaddr: 0x%08X\n", dlsymaddr);
	}

    inject_info->mprotectaddr = mprotectaddr;
    inject_info->dlopenaddr = dlopenaddr;
    inject_info->dlcloseaddr = dlcloseaddr;
    inject_info->dlsymaddr = dlsymaddr;
    return 0;
}

#define ALIGN(p) (((uintptr_t)p + (sizeof(uintptr_t) - 1)) & ~(sizeof(uintptr_t)-1))

static void dump_regs(struct pt_regs2 regs){
	printf("R0: 0x%08X (arg0)\n", regs.ARM_r0);
	printf("R1: 0x%08X (arg1)\n", regs.ARM_r1);
	printf("R2: 0x%08X (arg2)\n", regs.ARM_r2);
	printf("LR: 0x%08X (return address)\n", regs.ARM_lr);
	printf("PC: 0x%08X (program counter)\n", regs.ARM_pc);
	printf("SP: 0x%08X (stack pointer)\n", regs.ARM_sp);
}

static int inject_lib(
        pid_t pid, const char *lib_name, int resident)
{
    inject_info_t inject_info;
	memset(&inject_info, 0x00, sizeof(inject_info));

	// Attach 
	if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0)
    {
		printf("cannot attach to %d, error!\n", pid);
		return -2;
	}
	waitpid(pid, NULL, 0);
	
    if(inject_prepare(pid, &inject_info) < 0)
    {
        return -1;
    }
	char buf[32];
	sprintf(buf, "/proc/%d/mem", pid);
	int fd = open(buf, O_WRONLY);
	if(fd <= 0)
    {
		printf("cannot open %s, error!\n", buf);
    	ptrace(PTRACE_DETACH, pid, 0, 0);
		return -3;
	}
    close(fd);
	
	struct pt_regs2 regs;
    ptrace(PTRACE_GETREGS, pid, 0, &regs);

    int nalloc = ALIGN(strlen(lib_name) + 1);

    char *extra = 0;
    int extra_len = init_extra(_argc, _argv, &extra);

    nalloc += extra_len;

    sc_t *sc = sc_alloc(nalloc);
    int sc_size = sc_get_size(sc);

	sc_ctx_t *ctx = sc_get_ctx(sc);
	ctx->dlopen = (void*)inject_info.dlopenaddr;
	ctx->dlclose = resident ? 0 : (void*)inject_info.dlcloseaddr;
	ctx->dlsym = (void*)inject_info.dlsymaddr;

	strcpy(ctx->lib_init, "lib_init");
	strcpy(ctx->lib_deinit, "lib_deinit");
	strcpy(ctx->lib_name, lib_name);
    {
        uintptr_t p = ALIGN((uintptr_t)(ctx->lib_name + strlen(lib_name) + 1));
        memcpy((void*)p, extra, extra_len);
    }

    sc_reg_save_t *reg_save = sc_get_reg_save(sc);
	#if defined(TARGET_ARM) || defined(TARGET_THUMB)
	reg_save->R0 = regs.ARM_r0;
	reg_save->R1 = regs.ARM_r1;
	reg_save->R2 = regs.ARM_r2;
	reg_save->R3 = regs.ARM_r3;
	reg_save->R4 = regs.ARM_r4;
	reg_save->R5 = regs.ARM_r5;
	reg_save->R6 = regs.ARM_r6;
	reg_save->R7 = regs.ARM_r7;
	reg_save->R8 = regs.ARM_r8;
	reg_save->R9 = regs.ARM_r9;
	reg_save->R10 = regs.ARM_r10;
	reg_save->FP = regs.ARM_fp;
	reg_save->IP = regs.ARM_ip; //Intra Procedure call scratch Register
	reg_save->LR = regs.ARM_lr;
	reg_save->PC = regs.ARM_pc;
	reg_save->SP = regs.ARM_sp;
	#elif defined(TARGET_AMD64)
	reg_save->RAX = regs.rax;
	reg_save->RBX = regs.rbx;
	reg_save->RCX = regs.rcx;
	reg_save->RDX = regs.rdx;
	reg_save->RDI = regs.rdi;
	reg_save->RSI = regs.rsi;
	reg_save->RBP = regs.rbp;
	reg_save->RIP = regs.rip;
	reg_save->R8 = regs.r8;
	reg_save->R9 = regs.r9;
	reg_save->R10 = regs.r10;
	reg_save->R11 = regs.r11;
	reg_save->R12 = regs.r12;
	reg_save->R13 = regs.r13;
	reg_save->R14 = regs.r14;
	reg_save->R15 = regs.r15;
	#endif

	if (debug) {
		dump_regs(regs);
	}

	if (debug)
		printf("stack: 0x%08X-0x%08X, length = %d\n", stack_start, stack_end, stack_end-stack_start);

#if defined(TARGET_ARM) || defined(TARGET_THUMB)		
	// write code to stack
	uintptr_t codeaddr = regs.ARM_sp - sc_size;
#elif defined(TARGET_AMD64)
	uintptr_t codeaddr = regs.rsp - sc_size;
#endif

	if(debug){
		printf("writing 0x%08X bytes at 0x%x\n", sc_size, codeaddr);
	}

	uint8_t *shell_code = sc_get(sc);

	//-- STACK --
	//[ARM_sp - sc_size]
	//.....
	//[ARM_sp]
	if(write_mem(pid, (unsigned long*)shell_code, sc_size/sizeof(long), codeaddr) < 0) 
    {
		printf("cannot write code, error!\n");
    	ptrace(PTRACE_DETACH, pid, 0, 0);
		return -4;
	}

	if (debug)
		printf("executing injection code at 0x%x\n", codeaddr);

	// offset (if any) for the shellcode entry point
	codeaddr += SC_OFFSET(_SHELL_CODE_MAIN);

#if defined(TARGET_ARM) || defined(TARGET_THUMB)	
	// reserve stack space (used for the code we just wrote) - equivalent to alloca
	regs.ARM_sp = regs.ARM_sp - sc_size;

	// call mprotect() to make stack executable
	regs.ARM_r0 = stack_start; // want to make stack executable
	//printf("r0 %x\n", regs.ARM_r0);
	regs.ARM_r1 = stack_end - stack_start; // stack size
	//printf("mprotect(%x, %d, ALL)\n", regs.ARM_r0, regs.ARM_r1);
	regs.ARM_r2 = PROT_READ|PROT_WRITE|PROT_EXEC; // protections
	regs.ARM_lr = codeaddr; // points to loading and fixing code
	regs.ARM_pc = inject_info.mprotectaddr; // execute mprotect()

	if (debug) {
		dump_regs(regs);
	}

#elif defined(TARGET_AMD64)
	*(uintptr_t *)(&_SC_STACK + 4096 - 8) = &_SC_MAIN;
	regs.rsp = &_SC_STACK + 4096 - 8;
	regs.rbp = &_SC_STACK + 4096 - 8;
	//regs.rsp = regs.rsp - sc_size;
	//regs.rbp = regs.rsp - sc_size;
	regs.rdi = stack_start;
	regs.rsi = stack_end - stack_start;
	regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;
	regs.rip = inject_info.mprotectaddr;
#endif
	
	// detach and continue
	ptrace(PTRACE_SETREGS, pid, 0, &regs);
	ptrace(PTRACE_DETACH, pid, 0, 0);

	if(debug)
		printf("library injection completed!\n");

    if(extra)
        free(extra);

    return 0;
}
