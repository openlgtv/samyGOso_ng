SECTIONS
{
	.sc : {
		_START_OF_SHELL_CODE = .;
		KEEP(*(.sc));
		_END_OF_SHELL_CODE = .;
	}
}
INSERT AFTER .text;