.intel_syntax noprefix
.section .sc, "wx"
.globl _SC_STACK
.globl _START_OF_SHELL_CODE
.globl _SC_MAIN
.globl _SHELL_CODE
.globl _SHELL_CODE_REG_SAVE
.globl _SHELL_CODE_CTX
.globl _END_OF_SHELL_CODE

_START_OF_SHELL_CODE:
_SC_MAIN:
	# Load the context in R0
	mov RDI, qword ptr[rip + _SHELL_CODE_CTX]
	# Call the C part of the loader
	call _SC_FINALIZE
	# Restore registers
	mov RAX, qword ptr[rip + L_RAX]
	mov RBX, qword ptr[rip + L_RBX]
	mov RCX, qword ptr[rip + L_RCX]
	mov RDX, qword ptr[rip + L_RDX]
	mov RDI, qword ptr[rip + L_RDI]
	mov R8, qword ptr[rip + L_R8]
	mov R9, qword ptr[rip + L_R9]
	mov R10, qword ptr[rip + L_R10]
	mov R11, qword ptr[rip + L_R11]
	mov R12, qword ptr[rip + L_R12]
	mov R13, qword ptr[rip + L_R13]
	mov R14, qword ptr[rip + L_R14]
	mov R15, qword ptr[rip + L_R15]
	mov RSI, qword ptr[rip + L_RSI]
	mov RBP, qword ptr[rip + L_RBP]
	pushq qword ptr[rip + L_RIP]
	retq

_SHELL_CODE_REG_SAVE:
	L_RAX: .word 0
	L_RBX: .word 0
	L_RCX: .word 0
	L_RDX: .word 0
	L_RDI: .word 0
	L_RSI: .word 0
	L_RBP: .word 0
	L_RIP: .word 0
	L_R8: .word 0
	L_R9: .word 0
	L_R10: .word 0
	L_R11: .word 0
	L_R12: .word 0
	L_R13: .word 0
	L_R14: .word 0
	L_R15: .word 0

_SHELL_CODE_CTX:
	L_dlopen: .quad 0
	L_dlsym: .quad 0
	L_dlclose: .quad 0
	.lib: .quad 0
	.fn_init: .quad 0
	L_lib_init: .fill 16, 1, 0
	L_lib_deinit: .fill 16, 1, 0
	L_soname: .fill 256, 1, 0

_END_OF_SHELL_CODE:
_SC_STACK:
.fill 4096, 1, 0
.fill 128, 1, 0