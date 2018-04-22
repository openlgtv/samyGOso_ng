SECTIONS
{
	.sc : {
		. = ALIGN(4);
		_START_OF_SHELL_CODE = .;
		KEEP(*(.sc));
		KEEP(*(.sc.c));
		_END_OF_SHELL_CODE = .;
	}
}
INSERT AFTER .text;