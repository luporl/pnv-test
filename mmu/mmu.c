#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "console.h"

/*
 * Apparently, Microwatt never updates RC bits, but just raise an
 * exception when they must be updated, leaving the task to the OS
 * (https://github.com/antonblanchard/microwatt/blob/master/mmu.vhdl#L402).
 * This is not the case with other POWER9 implementations, as the one
 * emulated by QEMU, so skip RC tests.
 */
#define SKIP_RC_TESTS

/*
 * Flag that indicate if QEMU has the needed tlbie fix (i.e., it is able to
 * flush the TLB in the same Translation Block).
 * If not, a workaround is used in the needed tests.
 */
#define HAS_TLBIE_FIX	0

#define MSR_LE	0x1
#define MSR_DR	0x10
#define MSR_IR	0x20
#define MSR_HV	0x1000000000000000ul
#define MSR_SF	0x8000000000000000ul

#ifdef __LITTLE_ENDIAN__
#define MSR_DFLT	(MSR_SF | MSR_HV | MSR_LE)
#else
#define MSR_DFLT	(MSR_SF | MSR_HV)
#endif

extern int test_read(long *addr, long *ret, long init);
extern int test_write(long *addr, long val);
extern int test_dcbz(long *addr);
extern int test_exec(int testno, unsigned long pc, unsigned long msr);

#define XSTR(x)	#x
#define STR(x)	XSTR(x)

#define RIC_TLB	0
#define RIC_PWC	1
#define RIC_ALL	2

#define PRS	1

#define IS(x)	((unsigned long)(x) << 10)
#define IS_VA	IS(0)
#define IS_PID	IS(1)
#define IS_LPID	IS(2)
#define IS_ALL	IS(3)

#define TLBIE_5(rb, rs, ric, prs, r)			\
	__asm__ volatile(".long 0x7c000264 | "		\
		"%0 << 21 | "				\
		STR(ric) " << 18 | "			\
		STR(prs) " << 17 | "			\
		STR(r) "<< 16 | "			\
		"%1 << 11"				\
		: : "r" (rs), "r" (rb) : "memory")

static inline void tlbie_all(int prs)
{
	if (prs)
		TLBIE_5(IS_ALL, 0, RIC_ALL, 1, 1);
	else
		TLBIE_5(IS_ALL, 0, RIC_ALL, 0, 1);
}

static inline void tlbie_va_nosync(unsigned long va, int prs)
{
	va &= ~0xffful;

	if (prs)
		TLBIE_5(IS_VA | va, 0, RIC_TLB, 1, 1);
	else
		TLBIE_5(IS_VA | va, 0, RIC_TLB, 0, 1);
}

static inline void tlbie_sync()
{
	__asm__ volatile("eieio; tlbsync; ptesync" : : : "memory");
}

static inline void tlbie_va(unsigned long va, int prs)
{
	tlbie_va_nosync(va, prs);
	tlbie_sync();
}

#define DSISR	18
#define DAR	19
#define SRR0	26
#define SRR1	27
#define PID	48
#define LPCR	318
#define PTCR	464

#define PPC_BIT(x)	(0x8000000000000000ul >> (x))

#define LPCR_UPRT	PPC_BIT(41)
#define LPCR_HR		PPC_BIT(43)

#define PATE_HR		PPC_BIT(0)

static inline unsigned long mfspr(int sprnum)
{
	long val;

	__asm__ volatile("mfspr %0,%1" : "=r" (val) : "i" (sprnum));
	return val;
}

static inline void mtspr(int sprnum, unsigned long val)
{
	__asm__ volatile("mtspr %0,%1" : : "i" (sprnum), "r" (val));
}

static inline unsigned long mfmsr(void)
{
	unsigned long ret;

	__asm__ volatile("mfmsr %0" : "=r"(ret));
	return ret;
}

static inline void mtmsrd(unsigned long msr)
{
	__asm__ volatile("mtmsrd %0" : : "r"(msr));
}

static inline void store_pte(unsigned long *p, unsigned long pte)
{
#ifdef __LITTLE_ENDIAN__
	__asm__ volatile("stdbrx %1,0,%0" : : "r" (p), "r" (pte) : "memory");
#else
	__asm__ volatile("stdx   %1,0,%0" : : "r" (p), "r" (pte) : "memory");
#endif
	__asm__ volatile("ptesync" : : : "memory");
}

void print_string(const char *str)
{
	for (; *str; ++str)
		putchar(*str);
}

void print_hex(unsigned long val)
{
	int i, x;

	for (i = 60; i >= 0; i -= 4) {
		x = (val >> i) & 0xf;
		if (x >= 10)
			putchar(x + 'a' - 10);
		else
			putchar(x + '0');
	}
}

// i < 100
void print_test_number(int i)
{
	print_string("test ");
	putchar(48 + i/10);
	putchar(48 + i%10);
	putchar(':');
}

#define CACHE_LINE_SIZE	64

void zero_memory(void *ptr, unsigned long nbytes)
{
	unsigned long nb, i, nl;
	void *p;

	for (; nbytes != 0; nbytes -= nb, ptr += nb) {
		nb = -((unsigned long)ptr) & (CACHE_LINE_SIZE - 1);
		if (nb == 0 && nbytes >= CACHE_LINE_SIZE) {
			nl = nbytes / CACHE_LINE_SIZE;
			p = ptr;
			for (i = 0; i < nl; ++i) {
				__asm__ volatile("dcbz 0,%0" : : "r" (p) : "memory");
				p += CACHE_LINE_SIZE;
			}
			nb = nl * CACHE_LINE_SIZE;
		} else {
			if (nb > nbytes)
				nb = nbytes;
			for (i = 0; i < nb; ++i)
				((unsigned char *)ptr)[i] = 0;
		}
	}
}

#define PAGE_SHIFT	12
#define PAGE_SIZE	(1ul << PAGE_SHIFT)

/* Partition Page Dir params */
#define PPD_L1_BITS	5
#define PPD_L2_BITS	14	/* virtual level 2 PGD address bits */
#define PPD_PA_INC	(1ul << (PAGE_SHIFT + PPD_L2_BITS))

#define RPTE_V		PPC_BIT(0)
#define RPTE_L		PPC_BIT(1)
#define RPTE_RPN_MASK	0x01fffffffffff000ul
#define RPTE_R		PPC_BIT(55)
#define RPTE_C		PPC_BIT(56)
#define RPTE_PRIV	PPC_BIT(60)
#define RPTE_RD		PPC_BIT(61)
#define RPTE_RW		PPC_BIT(62)
#define RPTE_EX		PPC_BIT(63)
#define RPTE_PERM_ALL	(RPTE_RD | RPTE_RW | RPTE_EX)

#define PERM_EX		RPTE_EX
#define PERM_WR		RPTE_RW
#define PERM_RD		RPTE_RD
#define PERM_PRIV	RPTE_PRIV
#define ATTR_NC		0x020
#define CHG		RPTE_C
#define REF		RPTE_R

#define DFLT_PERM	(PERM_WR | PERM_RD | REF | CHG)

/*
 * Set up an MMU translation tree using memory starting at the 64k point.
 * We use 2 levels, mapping 2GB (the minimum size possible), with a
 * 8kB PGD level pointing to 4kB PTE pages.
 */
unsigned long *pgdir = (unsigned long *) 0x10000;
unsigned long *proc_tbl = (unsigned long *) 0x12000;
unsigned long *part_tbl = (unsigned long *) 0x13000;
unsigned long *part_pgdir = (unsigned long *) 0x14000;
unsigned long free_ptr = 0x15000;
void *eas_mapped[4];
int neas_mapped;

void init_process_table(void)
{
	zero_memory(proc_tbl, 512 * sizeof(unsigned long));

	mtspr(PID, 1);
	zero_memory(pgdir, 1024 * sizeof(unsigned long));

	/* RTS = 0 (2GB address space), RPDS = 10 (1024-entry top level) */
	store_pte(&proc_tbl[2 * 1], (unsigned long) pgdir | 10);
}

void init_partition_table(void)
{
	int i, n;
	unsigned long pa, pte;

	/* Select Radix MMU (HR), with HW process table */
	mtspr(LPCR, mfspr(LPCR) | LPCR_UPRT | LPCR_HR);

	/*
	 * Set up partition page dir, needed to translate process table
	 * addresses.
	 * We use only 1 level, mapping 2GB 1-1, with 32 64M pages.
	 */
	zero_memory(part_tbl, PAGE_SIZE);
	store_pte(&part_tbl[0], PATE_HR | (unsigned long) part_pgdir |
			PPD_L1_BITS);

	for (i = 0, n = 1 << PPD_L1_BITS, pa = 0;
			i < n; i++, pa += PPD_PA_INC) {
		pte = RPTE_V | RPTE_L | (pa & RPTE_RPN_MASK) | RPTE_PERM_ALL;
		store_pte(&part_pgdir[i], pte);
	}

	store_pte(&part_tbl[1], (unsigned long)proc_tbl);
	mtspr(PTCR, (unsigned long)part_tbl);

	tlbie_all(0);	/* invalidate all TLB entries */
}

void init_mmu(void)
{
	init_partition_table();
	init_process_table();
}

static unsigned long *read_pgd(unsigned long i)
{
	unsigned long ret;

#ifdef __LITTLE_ENDIAN__
	__asm__ volatile("ldbrx %0,%1,%2" : "=r" (ret) : "b" (pgdir),
			 "r" (i * sizeof(unsigned long)));
#else
	__asm__ volatile("ldx   %0,%1,%2" : "=r" (ret) : "b" (pgdir),
			 "r" (i * sizeof(unsigned long)));
#endif
	return (unsigned long *) (ret & 0x00ffffffffffff00);
}

void map(void *ea, void *pa, unsigned long perm_attr)
{
	unsigned long epn = (unsigned long) ea >> 12;
	unsigned long i, j;
	unsigned long *ptep;

	i = (epn >> 9) & 0x3ff;
	j = epn & 0x1ff;
	if (pgdir[i] == 0) {
		zero_memory((void *)free_ptr, 512 * sizeof(unsigned long));
		store_pte(&pgdir[i], 0x8000000000000000 | free_ptr | 9);
		free_ptr += 512 * sizeof(unsigned long);
	}
	ptep = read_pgd(i);
	store_pte(&ptep[j], 0xc000000000000000 | ((unsigned long)pa & 0x00fffffffffff000) | perm_attr);
	eas_mapped[neas_mapped++] = ea;
}

static void unmap_noinval(void *ea)
{
	unsigned long epn = (unsigned long) ea >> 12;
	unsigned long i, j;
	unsigned long *ptep;

	i = (epn >> 9) & 0x3ff;
	j = epn & 0x1ff;
	if (pgdir[i] == 0)
		return;
	ptep = read_pgd(i);
	store_pte(&ptep[j], 0);
}

void unmap(void *ea)
{
	unmap_noinval(ea);
	tlbie_va((unsigned long)ea, PRS);
}

void unmap_all(void)
{
	int i;

	for (i = 0; i < neas_mapped; ++i)
		unmap(eas_mapped[i]);
	neas_mapped = 0;
}

int mmu_test_1(void)
{
	long *ptr = (long *) 0x123000;
	long val;

	/* this should fail */
	if (test_read(ptr, &val, 0xdeadbeefd00d))
		return 1;
	/* dest reg of load should be unchanged */
	if (val != 0xdeadbeefd00d)
		return 2;
	/* DAR and DSISR should be set correctly */
	if (mfspr(DAR) != (long) ptr || mfspr(DSISR) != 0x40000000)
		return 3;
	return 0;
}

int mmu_test_2(void)
{
	long *mem = (long *) 0x8000;
	long *ptr = (long *) 0x124000;
	long *ptr2 = (long *) 0x1124000;
	long val;

	/* create PTE */
	map(ptr, mem, DFLT_PERM);
	/* initialize the memory content */
	mem[33] = 0xbadc0ffee;
	/* this should succeed and be a cache miss */
	if (!test_read(&ptr[33], &val, 0xdeadbeefd00d))
		return 1;
	/* dest reg of load should have the value written */
	if (val != 0xbadc0ffee)
		return 2;
	/* load a second TLB entry in the same set as the first */
	map(ptr2, mem, DFLT_PERM);
	/* this should succeed and be a cache hit */
	if (!test_read(&ptr2[33], &val, 0xdeadbeefd00d))
		return 3;
	/* dest reg of load should have the value written */
	if (val != 0xbadc0ffee)
		return 4;
	/* check that the first entry still works */
	if (!test_read(&ptr[33], &val, 0xdeadbeefd00d))
		return 5;
	if (val != 0xbadc0ffee)
		return 6;
	return 0;
}

int mmu_test_3(void)
{
	long *mem = (long *) 0x9000;
	long *ptr = (long *) 0x14a000;
	long val;

	/* create PTE */
	map(ptr, mem, DFLT_PERM);
	/* initialize the memory content */
	mem[45] = 0xfee1800d4ea;
	/* this should succeed and be a cache miss */
	if (!test_read(&ptr[45], &val, 0xdeadbeefd0d0))
		return 1;
	/* dest reg of load should have the value written */
	if (val != 0xfee1800d4ea)
		return 2;
	/* remove the PTE */
	unmap(ptr);
	/* this should fail */
	if (test_read(&ptr[45], &val, 0xdeadbeefd0d0))
		return 3;
	/* dest reg of load should be unchanged */
	if (val != 0xdeadbeefd0d0)
		return 4;
	/* DAR and DSISR should be set correctly */
	if (mfspr(DAR) != (long) &ptr[45] || mfspr(DSISR) != 0x40000000)
		return 5;
	return 0;
}

int mmu_test_4(void)
{
	long *mem = (long *) 0xa000;
	long *ptr = (long *) 0x10b000;
	long *ptr2 = (long *) 0x110b000;
	long val;

	/* create PTE */
	map(ptr, mem, DFLT_PERM);
	/* initialize the memory content */
	mem[27] = 0xf00f00f00f00;
	/* this should succeed and be a cache miss */
	if (!test_write(&ptr[27], 0xe44badc0ffee))
		return 1;
	/* memory should now have the value written */
	if (mem[27] != 0xe44badc0ffee)
		return 2;
	/* load a second TLB entry in the same set as the first */
	map(ptr2, mem, DFLT_PERM);
	/* this should succeed and be a cache hit */
	if (!test_write(&ptr2[27], 0x6e11ae))
		return 3;
	/* memory should have the value written */
	if (mem[27] != 0x6e11ae)
		return 4;
	/* check that the first entry still exists */
	/* (assumes TLB is 2-way associative or more) */
	if (!test_read(&ptr[27], &val, 0xdeadbeefd00d))
		return 5;
	if (val != 0x6e11ae)
		return 6;
	return 0;
}

int mmu_test_5(void)
{
	long *mem = (long *) 0xbffd;
	long *ptr = (long *) 0x39fffd;
	long val;

	/* create PTE */
	map(ptr, mem, DFLT_PERM);
	/* this should fail */
	if (test_read(ptr, &val, 0xdeadbeef0dd0))
		return 1;
	/* dest reg of load should be unchanged */
	if (val != 0xdeadbeef0dd0)
		return 2;
	/* DAR and DSISR should be set correctly */
	if (mfspr(DAR) != ((long)ptr & ~0xfff) + 0x1000 || mfspr(DSISR) != 0x40000000)
		return 3;
	return 0;
}

int mmu_test_6(void)
{
	long *mem = (long *) 0xbffd;
	long *ptr = (long *) 0x39fffd;

	/* create PTE */
	map(ptr, mem, DFLT_PERM);
	/* initialize memory */
	*mem = 0x123456789abcdef0;
	/* this should fail */
	if (test_write(ptr, 0xdeadbeef0dd0))
		return 1;
	/* DAR and DSISR should be set correctly */
	if (mfspr(DAR) != ((long)ptr & ~0xfff) + 0x1000 || mfspr(DSISR) != 0x42000000)
		return 2;
	return 0;
}

int mmu_test_7(void)
{
	long *mem = (long *) 0x8000;
	long *ptr = (long *) 0x124000;
	long val;

	*mem = 0x123456789abcdef0;
	/* create PTE without R or C */
	map(ptr, mem, PERM_RD | PERM_WR);
	/* this should fail */
	if (test_read(ptr, &val, 0xdeadd00dbeef))
		return 1;
	/* dest reg of load should be unchanged */
	if (val != 0xdeadd00dbeef)
		return 2;
	/* DAR and DSISR should be set correctly */
	if (mfspr(DAR) != (long) ptr || mfspr(DSISR) != 0x00040000)
		return 3;
	/* this should fail */
	if (test_write(ptr, 0xdeadbeef0dd0))
		return 4;
	/* DAR and DSISR should be set correctly */
	if (mfspr(DAR) != (long)ptr || mfspr(DSISR) != 0x02040000)
		return 5;
	/* memory should be unchanged */
	if (*mem != 0x123456789abcdef0)
		return 6;
	return 0;
}

int mmu_test_8(void)
{
	long *mem = (long *) 0x8000;
	long *ptr = (long *) 0x124000;
	long val;

	*mem = 0x123456789abcdef0;
	/* create PTE with R but not C */
	map(ptr, mem, REF | PERM_RD | PERM_WR);
	/* this should succeed */
	if (!test_read(ptr, &val, 0xdeadd00dbeef))
		return 1;
	/* this should fail */
	if (test_write(ptr, 0xdeadbeef0dd1))
		return 2;
	/* DAR and DSISR should be set correctly */
	if (mfspr(DAR) != (long)ptr || mfspr(DSISR) != 0x02040000)
		return 3;
	/* memory should be unchanged */
	if (*mem != 0x123456789abcdef0)
		return 4;
	return 0;
}

int mmu_test_9(void)
{
	long *mem = (long *) 0x8000;
	long *ptr = (long *) 0x124000;
	long val;

	*mem = 0x123456789abcdef0;
	/* create PTE without read or write permission */
	map(ptr, mem, REF);
	/* this should fail */
	if (test_read(ptr, &val, 0xdeadd00dbeef))
		return 1;
	/* dest reg of load should be unchanged */
	if (val != 0xdeadd00dbeef)
		return 2;
	/* DAR and DSISR should be set correctly */
	if (mfspr(DAR) != (long) ptr || mfspr(DSISR) != 0x08000000)
		return 3;
	/* this should fail */
	if (test_write(ptr, 0xdeadbeef0dd1))
		return 4;
	/* DAR and DSISR should be set correctly */
	if (mfspr(DAR) != (long)ptr || mfspr(DSISR) != 0x0a000000)
		return 5;
	/* memory should be unchanged */
	if (*mem != 0x123456789abcdef0)
		return 6;
	return 0;
}

int mmu_test_10(void)
{
	long *mem = (long *) 0x8000;
	long *ptr = (long *) 0x124000;
	long val;

	*mem = 0x123456789abcdef0;
	/* create PTE with read but not write permission */
	map(ptr, mem, REF | PERM_RD);
	/* this should succeed */
	if (!test_read(ptr, &val, 0xdeadd00dbeef))
		return 1;
	/* this should fail */
	if (test_write(ptr, 0xdeadbeef0dd1))
		return 2;
	/* DAR and DSISR should be set correctly */
	if (mfspr(DAR) != (long)ptr || mfspr(DSISR) != 0x0a000000)
		return 3;
	/* memory should be unchanged */
	if (*mem != 0x123456789abcdef0)
		return 4;
	return 0;
}

int mmu_test_11(void)
{
	unsigned long ptr = 0x523000;

	/* this should fail */
	if (test_exec(0, ptr, MSR_DFLT | MSR_IR))
		return 1;
	/* SRR0 and SRR1 should be set correctly */
	if (mfspr(SRR0) != (long) ptr ||
	    mfspr(SRR1) != (MSR_DFLT | 0x40000000 | MSR_IR))
		return 2;
	return 0;
}

int mmu_test_12(void)
{
	unsigned long mem = 0x1000;
	unsigned long ptr = 0x324000;
	unsigned long ptr2 = 0x1324000;

	/* create PTE */
	map((void *)ptr, (void *)mem, PERM_EX | REF);
	/* this should succeed and be a cache miss */
	if (!test_exec(0, ptr, MSR_DFLT | MSR_IR))
		return 1;
	/* create a second PTE */
	map((void *)ptr2, (void *)mem, PERM_EX | REF);
	/* this should succeed and be a cache hit */
	if (!test_exec(0, ptr2, MSR_DFLT | MSR_IR))
		return 2;
	return 0;
}

int mmu_test_13(void)
{
	unsigned long mem = 0x1000;
	unsigned long ptr = 0x349000;
	unsigned long ptr2 = 0x34a000;

	/* create a PTE */
	map((void *)ptr, (void *)mem, PERM_EX | REF);
	/* this should succeed */
	if (!test_exec(1, ptr, MSR_DFLT | MSR_IR))
		return 1;
	/* invalidate the PTE */
	unmap((void *)ptr);
	/* install a second PTE */
	map((void *)ptr2, (void *)mem, PERM_EX | REF);
	/* this should fail */
	if (test_exec(1, ptr, MSR_DFLT | MSR_IR))
		return 2;
	/* SRR0 and SRR1 should be set correctly */
	if (mfspr(SRR0) != (long) ptr ||
	    mfspr(SRR1) != (MSR_DFLT | 0x40000000 | MSR_IR))
		return 3;
	return 0;
}

int mmu_test_14(void)
{
	unsigned long mem = 0x1000;
	unsigned long mem2 = 0x2000;
	unsigned long ptr = 0x30a000;
	unsigned long ptr2 = 0x30b000;

	/* create a PTE */
	map((void *)ptr, (void *)mem, PERM_EX | REF);
	/* this should fail due to second page not being mapped */
	if (test_exec(2, ptr, MSR_DFLT | MSR_IR))
		return 1;
	/* SRR0 and SRR1 should be set correctly */
	if (mfspr(SRR0) != ptr2 ||
	    mfspr(SRR1) != (MSR_DFLT | 0x40000000 | MSR_IR))
		return 2;
	/* create a PTE for the second page */
	map((void *)ptr2, (void *)mem2, PERM_EX | REF);
	/* this should succeed */
	if (!test_exec(2, ptr, MSR_DFLT | MSR_IR))
		return 3;
	return 0;
}

int mmu_test_15(void)
{
	unsigned long mem = 0x1000;
	unsigned long ptr = 0x324000;

	/* create a PTE without execute permission */
	map((void *)ptr, (void *)mem, DFLT_PERM);
	/* this should fail */
	if (test_exec(0, ptr, MSR_DFLT | MSR_IR))
		return 1;
	/* SRR0 and SRR1 should be set correctly */
	if (mfspr(SRR0) != ptr ||
	    mfspr(SRR1) != (MSR_DFLT | 0x10000000 | MSR_IR))
		return 2;
	return 0;
}

int mmu_test_16(void)
{
	unsigned long mem = 0x1000;
	unsigned long mem2 = 0x2000;
	unsigned long ptr = 0x30a000;
	unsigned long ptr2 = 0x30b000;

	/* create a PTE */
	map((void *)ptr, (void *)mem, PERM_EX | REF);
	/* create a PTE for the second page without execute permission */
	map((void *)ptr2, (void *)mem2, PERM_RD | REF);
	/* this should fail due to second page being no-execute */
	if (test_exec(2, ptr, MSR_DFLT | MSR_IR))
		return 1;
	/* SRR0 and SRR1 should be set correctly */
	if (mfspr(SRR0) != ptr2 ||
	    mfspr(SRR1) != (MSR_DFLT | 0x10000000 | MSR_IR))
		return 2;
	/* create a PTE for the second page with execute permission */
	map((void *)ptr2, (void *)mem2, PERM_RD | PERM_EX | REF);
	/* this should succeed */
	if (!test_exec(2, ptr, MSR_DFLT | MSR_IR))
		return 3;
	return 0;
}

int mmu_test_17(void)
{
	unsigned long mem = 0x1000;
	unsigned long ptr = 0x349000;

#ifndef SKIP_RC_TESTS
	/* create a PTE without the ref bit set */
	map((void *)ptr, (void *)mem, PERM_EX);
	/* this should fail */
	if (test_exec(2, ptr, MSR_DFLT | MSR_IR))
		return 1;
	/* SRR0 and SRR1 should be set correctly */
	if (mfspr(SRR0) != (long) ptr ||
	    mfspr(SRR1) != (MSR_DFLT | 0x00040000 | MSR_IR))
		return 2;
	unmap((void *)ptr);
#endif

	/* create a PTE without ref or execute permission */
	map((void *)ptr, (void *)mem, 0);
	/* this should fail */
	if (test_exec(2, ptr, MSR_DFLT | MSR_IR))
		return 1;
	/* SRR0 and SRR1 should be set correctly */
	/* RC update fail bit should not be set */
	if (mfspr(SRR0) != (long) ptr ||
	    mfspr(SRR1) != (MSR_DFLT | 0x10000000 | MSR_IR))
		return 2;
	return 0;
}

int mmu_test_18(void)
{
	long *mem = (long *) 0x8000;
	long *ptr = (long *) 0x124000;
	long *ptr2 = (long *) 0x1124000;

	/* create PTE */
	map(ptr, mem, DFLT_PERM);
	/* this should succeed and be a cache miss */
	if (!test_dcbz(&ptr[129]))
		return 1;
	/* create a second PTE */
	map(ptr2, mem, DFLT_PERM);
	/* this should succeed and be a cache hit */
	if (!test_dcbz(&ptr2[130]))
		return 2;
	return 0;
}

int mmu_test_19(void)
{
	long *mem = (long *) 0x8000;
	long *ptr = (long *) 0x124000;

	*mem = 0x123456789abcdef0;
	/* create PTE with read but not write permission */
	map(ptr, mem, REF | PERM_RD);
	/* this should fail and create a TLB entry */
	if (test_write(ptr, 0xdeadbeef0dd1))
		return 1;
	/* DAR and DSISR should be set correctly */
	if (mfspr(DAR) != (long)ptr || mfspr(DSISR) != 0x0a000000)
		return 2;
	/* Update the PTE to have write permission */
	map(ptr, mem, REF | CHG | PERM_RD | PERM_WR);
	/* this should succeed */
	if (!test_write(ptr, 0xdeadbeef0dd1))
		return 3;
	return 0;
}

int mmu_test_20(void)
{
	/*
	 * NOTE: keep everything that will be used with DR=1 on registers,
	 *       to avoid DSIs caused by unmaped memory.
	 */
	long *mem = (long *) 0xa00000;
	register long *ptr = (long *) 0x1230000;
	long val = 0x0123456789ABCDEF;
	long ret;
	register unsigned long msr, ret2;

	mtmsrd(MSR_DFLT);

	/* First, make sure we can write and read back the same value */
	map(ptr, mem, DFLT_PERM | PERM_EX);
	if (!test_write(ptr, val)) {
		return 1;
	}
	if (!test_read(ptr, &ret, 0xdeadbeefd00d)) {
		return 2;
	}
	if (ret != val) {
		return 3;
	}

	/* unmap ptr without invalidating TLB */
	unmap_noinval(ptr);

	/* Turn on Data Relocation (DR) */
	msr = mfmsr();
	mtmsrd(msr | MSR_DR);

	/*
	 * Invalidate TLB and try to read ptr right after.
	 * There was an issue that made tlbie + tlbie_sync take effect only
	 * in the next Translation Block.
	 */
	tlbie_va((unsigned long)ptr, PRS);

#if !HAS_TLBIE_FIX
	/*
	 * Introduce an unoptimizable branch, to force QEMU to break the
	 * current Translation Block (TB) and flush the TLB before starting
	 * to execute the next TB.
	 * Note that msr bit MSR_DR is already 0 (but the compiler doesn't
	 * know that), so this is a nop.
	 */
	if (msr & MSR_HV)
		msr &= ~MSR_DR;
#endif

	/* Try to read invalid entry and turn off DR */
	__asm__ volatile (
		"li      %0, 0x1234\n\t"
		"ld      %0, 0(%1)\n\t"
		"nop\n\t"
		/* land here if DSI occurred */
		"mtmsrd  %2"
		: "=&r"(ret2) : "r"(ptr), "r"(msr) : );

	if (ret2 == ret) {
		return 4;
	}

	return 0;
}

int fail = 0;

void do_test(int num, int (*test)(void))
{
	int ret;

	mtspr(DSISR, 0);
	mtspr(DAR, 0);
	unmap_all();
	print_test_number(num);
	ret = test();
	if (ret == 0) {
		print_string("PASS\r\n");
	} else {
		fail = 1;
		print_string("FAIL ");
		putchar(ret + '0');
		if (num <= 10 || num == 19) {
			print_string(" DAR=");
			print_hex(mfspr(DAR));
			print_string(" DSISR=");
			print_hex(mfspr(DSISR));
		} else {
			print_string(" SRR0=");
			print_hex(mfspr(SRR0));
			print_string(" SRR1=");
			print_hex(mfspr(SRR1));
		}
		print_string("\r\n");
	}
}

int main(void)
{
	console_init();
	init_mmu();

	do_test(1, mmu_test_1);
	do_test(2, mmu_test_2);
	do_test(3, mmu_test_3);
	do_test(4, mmu_test_4);
	do_test(5, mmu_test_5);
	do_test(6, mmu_test_6);

#ifndef SKIP_RC_TESTS
	do_test(7, mmu_test_7);
	do_test(8, mmu_test_8);
#else
	print_test_number(7);
	print_string("SKIP\r\n");
	print_test_number(8);
	print_string("SKIP\r\n");
#endif

	do_test(9, mmu_test_9);
	do_test(10, mmu_test_10);
	do_test(11, mmu_test_11);
	do_test(12, mmu_test_12);
	do_test(13, mmu_test_13);
	do_test(14, mmu_test_14);
	do_test(15, mmu_test_15);
	do_test(16, mmu_test_16);
	do_test(17, mmu_test_17);
	do_test(18, mmu_test_18);
	do_test(19, mmu_test_19);
	do_test(20, mmu_test_20);

	return fail;
}
