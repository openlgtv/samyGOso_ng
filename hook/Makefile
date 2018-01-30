-include ../toolchain.conf
-include ../install.conf

OUTDIR?=${PWD}/out-${ARCH}

TARGETS=libTimeShiftSeekPatch.so 
TARGETS:=$(TARGETS:%=${OUTDIR}/%)

CFLAGS += -fPIC -O2 -std=gnu99 -I../include
CFLAGS += -ldl



all: ${OUTDIR} ${TARGETS}
    
${OUTDIR}/libTimeShiftSeekPatch.so: timeshiftseekpatch.c hook.c $(wildcard *.h) $(wildcard ../include/*.h)
	$(CC) $(filter %.c %.cpp,$^) ${CFLAGS} -shared -Wl,-soname,$@ -o $@

${OUTDIR}:
	@mkdir -p ${OUTDIR}

clean:
	rm -f ${TARGETS}

ifeq (${TARGET_IP}, )
endif

install: ${TARGETS}
	ping -c1 -W1 -w1 ${TARGET_IP} >/dev/null && \
        lftp -v -c "open ${TARGET_IP};cd ${TARGET_DEST_DIR};mput $^;"

.PHONY: clean
.PHONY: install
