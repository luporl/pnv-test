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

#define STACK_TOP 0x2000
#define SPR_HSRR0 314

/* Load an immediate 64-bit value into a register */
#define LOAD_IMM64(r, e)			\
	lis     r,(e)@highest;			\
	ori     r,r,(e)@higher;			\
	rldicr  r,r, 32, 31;			\
	oris    r,r, (e)@h;			\
	ori     r,r, (e)@l;

	.section ".head","ax"

	. = 0
.global _start
_start:
	b	boot_entry

.global boot_entry
boot_entry:
	/* setup stack */
	LOAD_IMM64(%r1, STACK_TOP - 0x100)
	LOAD_IMM64(%r12, main)
	mtctr	%r12
	bctrl
	attn // terminate on exit
	b .

/*
 * These follow the list of possible alignment interrupt causes from
 * the ISA v3.1.
 */

/*
 * The thread is LE so Load/Store Multiple and Move Assist are not
 * supported. Should cause Alignment Interrupt. Need to use raw
 * opcodes because newer assemblers are too smart.
 */
#define LMW   .long 0xbb840000  /* lmw     r28,0(r4) */
#define STMW  .long 0xbf840000  /* stmw    r28,0(r4) */
#define LSWI  .long 0x7ca424aa  /* lswi    r5,r4,4   */
#define STSWI .long 0x7ca425aa  /* stswi   r5,r4,4   */
#define LSWX  .long 0x7ca4342a  /* lswx    r5,r4,r6  */
#define STSWX .long 0x7ca4352a  /* stswx   r5,r4,r6  */
#define LSWX  .long 0x7ca4342a  /* lswx    r5,r4,r6  */
#define STSWX .long 0x7ca4352a  /* stswx   r5,r4,r6  */

.global align_test_le
align_test_le:
	mr	%r4, %r3
	mr	%r10, %r3        /* Handler will check against DAR */
	li	%r3, 1

	li	%r9, . + 4
	LMW
	b	1f

	li	%r9, . + 4
	STMW
	b	1f

	li	%r9, . + 4
	LSWI
	b	1f

	li	%r9, . + 4
	STSWI
	b	1f

	li	%r6, 2           /* Setup for next two. Values don't matter */
	add	%r10, %r10, %r6
	mtxer	%r6

	li	%r9, . + 4
	LSWX
	b	1f

	li	%r9, . + 4
	STSWX
	b	1f

	li	%r3, 0
	blr
1:
	li	%r3, 1
	blr

/*
 * Even if the thread is LE, Move Assist with length 0 should *not*
 * cause Alignment Interrupt.
 */
.global align_test_le_move_assist_0
align_test_le_move_assist_0:
	mr	%r4, %r3
	mr	%r10, %r3        /* Handler will check against DAR */
	li	%r3, 1

	li	%r6, 0
	mtxer	%r6

	li	%r9, . + 4
	LSWX

	li	%r9, . + 4
	STSWX

	cmpdi	%r3, 0          /* the handler set this to 0. It should still be 1 */
	beq	1f

	li	%r3, 0
	blr
1:
	li	%r3, 1
	blr

/*
 * Atomic loads and stores have an alignment requirement. Test that an
 * Alignment Interrupt is being raised when we break those requirements.
 */
.global align_test_atomic
align_test_atomic:
	mr	%r4, %r3
	mr	%r7, %r3
	li	%r3, 1

	addi	%r4, %r7, 2      /* RA not a multiple of 4 or 8 */
	mr	%r10, %r4        /* Handler will check against DAR */

	li	%r9, . + 4
	lwat	%r5, %r4, 0
	b	1f

	li	%r9, . + 4
	ldat	%r5, %r4, 0
	b	1f

	li	%r9, . + 4
	stwat	%r5, %r4, 0
	b	1f

	li	%r9, . + 4
	stdat	%r5, %r4, 0
	b	1f

	rldicr	%r4, %r7, 0, 55  /* Align to 0x100 */

	ori	%r4, %r4, 0xfc   /* RA about to cross 32-byte boundary */
	mr	%r10, %r4        /* Handler will check against DAR */

	li	%r9, . + 4
	lwat	%r5, %r4, 24
	b	1f

	li	%r9, . + 4
	stwat	%r5, %r4, 24
	b	1f

	rldicr	%r4, %r7, 0, 55  /* Align to 0x100 */

	ori	%r4, %r4, 0xf8   /* RA about to cross 32-byte boundary */
	mr	%r10, %r4        /* Handler will check against DAR */

	li	%r9, . + 4
	ldat	%r5, %r4, 24
	b	1f

	li	%r9, . + 4
	stdat	%r5, %r4, 24
	b	1f

	li	%r3, 0
	blr
1:
	li	%r3, 1
	blr

/*
 * For the Alignment interrupt to trigger, the first word of the
 * prefixed instruction must be at an address that is 60 module 64,
 * i.e.: EA % 64 == 60. However, we cannot really UNalign a prefixed
 * instruction because the toolchain knows about the alignment
 * requirements and adds a nop where needed. So we're adding the raw
 * opcode for prefix instruction at the (in)correct address.
 */

/* pli   r3, 1 */
#define PLI_W1	.long	0x06000000
#define PLI_W2	.long	0x38600001

	. = 0x1b0
.global align_test_prefixed
align_test_prefixed:
	mr	%r4, %r3
	li	%r3, 1

	li	%r9, . + 4
	PLI_W1
	PLI_W2
	cmpdi	%r3, 2      /* No prefix support. Bail. */
	beq	1f
	blr

1:
	li	%r3, 0
	blr

/*
 * These should require RA + RB to be a multiple of word size.
 */
.global align_test_indexed
align_test_indexed:
	mr	%r4, %r3
	li	%r3, 1

	li	%r5, 1
	add	%r10, %r4, %r5
	li	%r9, . + 4
	lharx	%r4, %r4, %r5, 0
	b	1f

	li	%r9, . + 4
	lwarx	%r4, %r4, %r5, 0
	b	1f

	li	%r9, . + 4
	ldarx	%r4, %r4, %r5, 0
	b	1f

	li	%r9, . + 4
	lqarx	%r6, %r4, %r5, 0
	b	1f

	li	%r9, . + 4
	sthcx.	%r6, %r4, %r5
	b	1f

	li	%r9, . + 4
	stwcx.	%r6, %r4, %r5
	b	1f

	li	%r9, . + 4
	stdcx.	%r6, %r4, %r5
	b	1f

	li	%r9, . + 4
	stqcx.	%r6, %r4, %r5
	b	1f

	li	%r3, 0
	blr
1:
	li	%r3, 1
	blr

#define EXCEPTION(nr)		\
	.= nr			;\
	b	.

	/* More exception stubs */
	EXCEPTION(0x300)
	EXCEPTION(0x380)
	EXCEPTION(0x400)
	EXCEPTION(0x480)
	EXCEPTION(0x500)

	. = 0x600
	mtsprg0	%r4

	mfsrr0	%r3
	cmpd	%r3, %r9   /* SRR0 should have the instruction EA */
	bne	1f

	mfdar	%r3
	cmpd	%r3, %r10   /* DAR should have the computed EA */
	bne	1f

	li	%r4, 8     /* PASS: skip the bad instruction + 1 */
	b	2f
1:
	li	%r4, 4     /* FAIL: skip the bad instruction */
2:
	mfsrr0	%r3
	add	%r3, %r3, %r4
	mtsrr0  %r3

	li	%r3, 0
	mfsprg0	%r4
	rfid

	. = 0x700
	mfsrr0	%r3
	addi	%r3, %r3, 8  /* PASS: skip the bad instruction + 1 */
	mtsrr0  %r3
	li	%r3, 2       /* SKIP: unsupported instruction */
	rfid

	EXCEPTION(0x800)
	EXCEPTION(0x900)
	EXCEPTION(0x980)
	EXCEPTION(0xa00)
	EXCEPTION(0xb00)
	EXCEPTION(0xc00)
	EXCEPTION(0xd00)
	EXCEPTION(0xe00)
	EXCEPTION(0xe20)

	. = 0xe40
	mfspr	%r3, SPR_HSRR0
	addi	%r3, %r3, 8  /* PASS: skip the bad instruction + 1 */
	mtspr	SPR_HSRR0, %r3
	li	%r3, 2       /* SKIP: unsupported instruction */
	hrfid

	EXCEPTION(0xe60)
	EXCEPTION(0xe80)
	EXCEPTION(0xf00)
	EXCEPTION(0xf20)
	EXCEPTION(0xf40)
	EXCEPTION(0xf60)
	EXCEPTION(0xf80)
#if 0
	EXCEPTION(0x1000)
	EXCEPTION(0x1100)
	EXCEPTION(0x1200)
	EXCEPTION(0x1300)
	EXCEPTION(0x1400)
	EXCEPTION(0x1500)
	EXCEPTION(0x1600)
#endif
