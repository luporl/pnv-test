#ifndef _PNV_H
#define _PNV_H

#define LPC_BASE_ADDR	0x0006030000000000
#define LPC_IO_SPACE	0xd0010000
#define LPC_FW_SPACE	0xf0000000

#define UART_BASE       (LPC_BASE_ADDR + LPC_IO_SPACE + 0x3f8);

#endif
