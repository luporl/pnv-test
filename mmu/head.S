/* Copyright 2013-2014 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define HSRR0	314
#define HSRR1	315

/* Load an immediate 64-bit value into a register */
#define LOAD_IMM64(r, e)			\
	lis     r,(e)@highest;			\
	ori     r,r,(e)@higher;			\
	rldicr  r,r, 32, 31;			\
	oris    r,r, (e)@h;			\
	ori     r,r, (e)@l;

	.section ".head","ax"

	/*
	 * Microwatt currently enters in LE mode at 0x0, so we don't need to
	 * do any endian fix ups
	 */
	. = 0
_start:
	b start

	. = 0x10
.global start
start:
	# clear .bss
	LOAD_IMM64(%r10,__bss_start)
	LOAD_IMM64(%r11,__bss_end)
	subf	%r11,%r10,%r11
	addi	%r11,%r11,63
	srdi.	%r11,%r11,6
	beq	2f
	mtctr	%r11
1:	dcbz	0,%r10
	addi	%r10,%r10,64
	bdnz	1b

	# set stack pointer
2:	LOAD_IMM64(%r1,__stack_top)
	li	%r0,0
	stdu	%r0,-32(%r1)

	# install HV page table
	LOAD_IMM64(%r12, mmu_bootstrap)
	mtctr	%r12
	bctrl

	# clear HV
	LOAD_IMM64(%r11, ~0x1000000000000000)
	mfmsr	%r10
	and		%r10, %r10, %r11
	mtsrr1	%r10
	bl 1f
1:
	mflr	%r10
	addi	%r10, %r10, (2f - 1b)
	mtsrr0	%r10
	rfid
2:

	# call main
	LOAD_IMM64(%r12, main)
	mtctr	%r12
	bctrl
	attn // terminate on exit
	b .

.global hv_putchar
hv_putchar:
	mflr	%r0
	std		%r0, 16(%r1)
	stdu	%r1, -32(%r1)

	LOAD_IMM64(%r11, 0x1000000000000000)
	mfmsr	%r10
	and.	%r10, %r10, %r11
	bne		.is_hv

	li	%r0, 0x1234
	sc	1
	b	.ret

.is_hv:
	# putchar
	LOAD_IMM64(%r12, putchar)
	mtctr	%r12
	bctrl

.ret:
	addi	%r1, %r1, 32
	ld		%r10, 16(%r1)
	mtlr	%r10
	blr

sc_putchar:
	LOAD_IMM64(%r12, putchar)
	mtctr	%r12
	bctrl
	rfid

	/* Read a location with translation on */
	.globl	test_read
test_read:
	mfmsr	%r9
	ori	%r8,%r9,0x10	/* set MSR_DR */
	mtmsrd	%r8,0
	mr	%r6,%r3
	li	%r3,0
	ld	%r5,0(%r6)
	li	%r3,1
	/* land here if DSI occurred */
	mtmsrd	%r9,0
	std	%r5,0(%r4)
	blr

	/* Write a location with translation on */
	.globl	test_write
test_write:
	mfmsr	%r9
	ori	%r8,%r9,0x10	/* set MSR_DR */
	mtmsrd	%r8,0
	mr	%r6,%r3
	li	%r3,0
	std	%r4,0(%r6)
	li	%r3,1
	/* land here if DSI occurred */
	mtmsrd	%r9,0
	blr

	/* Do a dcbz with translation on */
	.globl	test_dcbz
test_dcbz:
	mfmsr	%r9
	ori	%r8,%r9,0x10	/* set MSR_DR */
	mtmsrd	%r8,0
	mr	%r6,%r3
	li	%r3,0
	dcbz	0,%r6
	li	%r3,1
	/* land here if DSI occurred */
	mtmsrd	%r9,0
	blr

	.globl	test_exec
test_exec:
	mtsrr0	%r4
	mtsrr1	%r5
	rfid

#define EXCEPTION(nr)		\
	.= nr			;\
	attn

	/* DSI vector - skip the failing instruction + the next one */
	. = 0x300
	mtsprg0	%r10
	mfsrr0	%r10
	addi	%r10,%r10,8
	mtsrr0	%r10
	rfid

	EXCEPTION(0x380)

	/*
	 * ISI vector - jump to LR to return from the test,
	 * with r3 cleared
	 */
	. = 0x400
	li	%r3,0
	blr

	/* More exception stubs */
	EXCEPTION(0x480)
	EXCEPTION(0x500)
	EXCEPTION(0x600)
	EXCEPTION(0x700)
	EXCEPTION(0x800)
	EXCEPTION(0x900)
	EXCEPTION(0x980)
	EXCEPTION(0xa00)
	EXCEPTION(0xb00)

	/*
	 * System call - used to exit from tests where MSR[PR]
	 * may have been set.
	 */
	. = 0xc00
	cmpdi	%r0, 0x1234
	beq		sc_putchar
	blr

	EXCEPTION(0xd00)
	EXCEPTION(0xe00)
	EXCEPTION(0xe20)
	EXCEPTION(0xe40)
	EXCEPTION(0xe60)
	EXCEPTION(0xe80)
	EXCEPTION(0xf00)
	EXCEPTION(0xf20)
	EXCEPTION(0xf40)
	EXCEPTION(0xf60)
	EXCEPTION(0xf80)

	. = 0x1000
	/*
	 * This page gets mapped at various locations and
	 * the tests try to execute from it.
	 * r3 contains the test number.
	 */
	.globl	test_start
test_start:
	nop
	nop
	cmpdi	%r3,1
	beq	test_1
	cmpdi	%r3,2
	beq	test_2
test_return:
	li	%r3,1
	sc

	. = 0x1ff8
	/* test a branch near the end of a page */
test_1:	b	test_return

	/* test flowing from one page to the next */
test_2:	nop
	b	test_return
