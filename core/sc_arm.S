.global _SHELL_CODE_MAIN
.global _SHELL_CODE_REG_SAVE
.global _SHELL_CODE_CTX
.section .sc

_SHELL_CODE_MAIN:
	# Load the context in R0
	ADR R0, _SHELL_CODE_CTX
	# Call the C part of the loader
	BL _SC_FINALIZE
	# Restore registers
	LDR SP, L_SP
	LDR R0, L_R0
	LDR R1, L_R1
	LDR R2, L_R2
	LDR R3, L_R3
	LDR R4, L_R4
	LDR R5, L_R5
	LDR R6, L_R6
	LDR R7, L_R7
	LDR R8, L_R8
	LDR R9, L_R9
	LDR R10, L_R10
	LDR FP, L_FP
	LDR IP, L_IP
	LDR LR, L_LR
	LDR PC, L_PC


_SHELL_CODE_REG_SAVE:
	L_R0:    .word 0
	L_R1:    .word 0
	L_R2:    .word 0
	L_R3:    .word 0
	L_R4:    .word 0
	L_R5:    .word 0
	L_R6:    .word 0
	L_R7:    .word 0
	L_R8:    .word 0
	L_R9:    .word 0
	L_R10:   .word 0
	L_FP:    .word 0
	L_IP:    .word 0
	L_LR:    .word 0
	L_PC:    .word 0
	L_SP:    .word 0

_SHELL_CODE_CTX:
	L_dlopen: .word 0
	L_dlsym: .word 0
	L_dlclose: .word 0
	.lib: .word 0
	.fn_init: .word 0
	L_lib_init: .fill 16, 1, 0
	L_lib_deinit: .fill 16, 1, 0
	L_soname: .fill 256, 1, 0
