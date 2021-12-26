SECTIONS
{
	_start = .;
	. = 0;
	.head : {
		KEEP(*(.head))
	}
	. = 0x2000;
	.text : { *(.text) }
	. = 0x3000;
	.data : { *(.data) }
	.bss : { *(.bss) }
}
