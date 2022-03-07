/* vim: noexpandtab */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "console.h"

void hv_putchar(int c);
#define putchar		hv_putchar

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

static inline void store_pte(unsigned long *p, unsigned long pte)
{
	__asm__ volatile("stdbrx %1,0,%0" : : "r" (p), "r" (pte) : "memory");
}

/* MMU bootstrap { */

#define PPC_BIT(x)	(0x8000000000000000ULL >> (x))

#define LPCR		318
#define LPCR_UPRT	PPC_BIT(41)	/* hw partition */
#define LPCR_HR		PPC_BIT(43)	/* host radix */
#define LPCR_GTSE	PPC_BIT(53)
#define LPCR_ILE	PPC_BIT(38)

#define PID			48
#define LPIDR		319
#define PTCR		464
#define HRMOR		313

#define PAT_HR		PPC_BIT(0)

#define MSR_SF		PPC_BIT(0)
#define MSR_HV		PPC_BIT(3)
#define MSR_DR		0x10
#define MSR_IR		0x20
#define MSR_LE		PPC_BIT(63)

#define RPTE_V		PPC_BIT(0)
#define RPTE_L		PPC_BIT(1)
#define RPTE_RPN_MASK	0x01FFFFFFFFFFF000
#define RPTE_R		PPC_BIT(55)
#define RPTE_C		PPC_BIT(56)
#define RPTE_PRIV	PPC_BIT(60)
#define RPTE_RD		PPC_BIT(61)
#define RPTE_RW		PPC_BIT(62)
#define RPTE_EX		PPC_BIT(63)

#define RPTE_DFLT_PERM	(RPTE_RD | RPTE_RW | RPTE_EX)

#define RT_SHIFT		31
#define PAGE_SHIFT		12
#define L1_SHIFT		5
#define L2_SHIFT		14
#define PA_INC			(1 << (PAGE_SHIFT + L2_SHIFT))

#define PERM_EX		0x001
#define PERM_WR		0x002
#define PERM_RD		0x004
#define PERM_PRIV	0x008
#define ATTR_NC		0x020
#define CHG		0x080
#define REF		0x100

#define DFLT_PERM	(PERM_WR | PERM_RD | REF | CHG)

#define xassert(cond)							\
	do {										\
		if (!(cond)) {							\
			print_string("assert failed: "		\
				#cond "\n");					\
			__asm__("attn");					\
		}										\
	} while (0)

static inline unsigned long mfmsr(void)
{
	long val;

	__asm__ volatile("mfmsr %0" : "=r" (val));
	return val;
}

/*
 * Partition Table Entry
 * 1
 * HR   - Host Radix
 * RTS  - Radix Tree Size (2^(RTS+31), 2G when RTS = 0)
 * RPDB - Root Page Directory Base
 * RPDS - Root Page Directory Size (2^(RPDS+3), RPDS >= 5)
 *        (looks like the size in bytes, with each entry taking 8 bytes)
 * 2
 * PRTB - Process Table Base
 * PRTS - Process Table Size (2^(12+PRTS))
 *
 * Process Table Entry
 * 1
 * RTS  - Radix Tree Size (2^(RTS+31), 2G when RTS = 0)
 * RPDB - Root Page Directory Base
 * RPDS - Root Page Directory Size (2^(RPDS+3), RPDS >= 5)
 * 2
 * Reserved
 */

/*
 * The first 16K (0x4000) of RAM are reserved for interrupt vectors and other
 * stuff.
 */

#define HV_BASE_ADDR		0x0400000
#define SV_BASE_ADDR		0x0010000
#define PAGE_SIZE			4096

/* Partition table: 4K is the minimum size */
#define PART_TBL			HV_BASE_ADDR
/* Hypervisor page dir: 256B, 32 entries */
#define HPGDIR				(PART_TBL + PAGE_SIZE)

/* Page dir: 8K, 1024 entries */
#define PGDIR				SV_BASE_ADDR
/* Process table: 4K is the minimum size */
#define PROC_TBL			(PGDIR + 2 * PAGE_SIZE)
/* part table */
#define FREE_PTR			(PROC_TBL + 2 * PAGE_SIZE)

#if FREE_PTR != 0x14000
#error XXXERR
#endif

unsigned long *proc_tbl = (unsigned long *) PROC_TBL;
unsigned long *pgdir = (unsigned long *) PGDIR;
unsigned long free_ptr = FREE_PTR;

unsigned long *part_tbl = (unsigned long *) PART_TBL;
unsigned long *hpgdir = (unsigned long *) HPGDIR;

void mmu_bootstrap(void)
{
	int i;
	unsigned long pa, pte;

	console_init();

	print_string("mmu_bootstrap\n");

	xassert(mfmsr() == (MSR_SF | MSR_HV | MSR_LE));
	xassert(mfspr(LPIDR) == 0);
	xassert(mfspr(PID) == 0);

	/* Make sure HRMOR is 0, so that HV real addresses are not offseted */
	xassert(mfspr(HRMOR) == 0);

	/*
	 * Virtualized Partition Memory (VPM) is always enabled when address
	 * translation is disabled. So if a guest real address can't be translated
	 * to host real address, (e.g., because no partition page table was
	 * configured), a Hypervisor Data Storage or a Hypervisor Instruction
	 * Storage will occur.
	 *
	 * When MSR_HV|MSR_IR|MSR_DR = 000, Virtual Real Addressing Mode is used.
	 * When HV=0 and PATE_HR=1, this consists in performing partition-scoped
	 * translation.
	 */

	/* Select Radix MMU (HR), with HW process table */
	mtspr(LPCR, mfspr(LPCR) | LPCR_UPRT | LPCR_HR | LPCR_GTSE | LPCR_ILE);

	/*
	 * Set up partition table.
	 *
	 * PATE #0:
	 * dword 1:
	 * HR=1
	 * RTS=0 = 2^13 = 2G
	 * RPBD=hpgdir
	 * RPDS=5 = 2^8 = 256 (32 entries)
	 * dword 2:
	 * PRTB=proc_tbl
	 * PRTS=0 = 2^12 = 4K
	 *
	 * PTCR:
	 * PATB=part_tbl
	 * PATS=0 = 2^12 = 4K (512 entries)
	 *
	 * XXX I guess a single partition is enough?
	 * 6.7.6.1 says that HR=1 LPID=0 HV=0 is unsupported
	 */
	zero_memory(part_tbl, PAGE_SIZE);
	store_pte(&part_tbl[0], PAT_HR | (unsigned long)hpgdir | 5);
	store_pte(&part_tbl[1], (unsigned long)proc_tbl);
	store_pte(&part_tbl[2], PAT_HR | (unsigned long)hpgdir | 5);
	store_pte(&part_tbl[3], (unsigned long)proc_tbl);
	mtspr(PTCR, (unsigned long)part_tbl);

	/*
	 * Set up hpgdir.
	 *
	 * First level maps 5 bits, has a sizeof 256B and 32 entries.
	 */

	for (i = 0, pa = 0; i < 32; i++, pa += PA_INC) {
		pte = RPTE_V | RPTE_L | (pa & RPTE_RPN_MASK) | RPTE_DFLT_PERM;
		store_pte(&hpgdir[i], pte);
	}

	/*
	 * Set up process table (later).
	 */
	zero_memory(proc_tbl, PAGE_SIZE);

#if 0
	zero_memory(pgdir, 1024 * sizeof(unsigned long));
	/* RTS = 0 (2GB address space), RPDS = 10 (1024-entry top level) */
	store_pte(&proc_tbl[2 * 1], (unsigned long) pgdir | 10);
	do_tlbie(0xc00, 0);	/* invalidate all TLB entries */
#endif

#if 0
	/*
	 * Set up process table, entry 1
	 *
	 * RTS = 0 (2GB address space), RPDS = 10 (1024-entry top level)
	 */
#endif

	mtspr(LPIDR, 1);
	print_string("mmu_bootstrap DONE\n");
}

/* MMU bootstrap } */

extern int test_read(long *addr, long *ret, long init);
extern int test_write(long *addr, long val);
extern int test_dcbz(long *addr);
extern int test_exec(int testno, unsigned long pc, unsigned long msr);

#define TLBIE_5(rb, rs, ric, prs, r)	\
	__asm__ volatile(".long 0x7c000264 | "		\
			"%0 << 21 | "								\
			#ric " << 18 | "							\
			#prs " << 17 | "							\
			#r "<< 16 | "								\
			"%1 << 11"									\
			: : "r" (rs), "r" (rb) : "memory")

static inline void do_tlbie(unsigned long rb, unsigned long rs)
{
	/* RIC=2 (invalidate all), PRS=1, R=1 */

	/* __asm__ volatile("tlbie %0,%1,2,1,1" : : "r" (rb), "r" (rs) :
	 * "memory"); */
	TLBIE_5(rb, rs, 2, 1, 1);
	__asm__ volatile("eieio; tlbsync; ptesync" : : : "memory");
}

#define DSISR	18
#define DAR	19
#define SRR0	26
#define SRR1	27

// i < 100
void print_test_number(int i)
{
	print_string("test ");
	putchar(48 + i/10);
	putchar(48 + i%10);
	putchar(':');
}

/*
 * Set up an MMU translation tree using memory starting at the 64k point.
 * We use 2 levels, mapping 2GB (the minimum size possible), with a
 * 8kB PGD level pointing to 4kB PTE pages.
 */
void *eas_mapped[4];
int neas_mapped;

void init_mmu(void)
{
	mtspr(PID, 1);
	zero_memory(pgdir, 1024 * sizeof(unsigned long));
	/* RTS = 0 (2GB address space), RPDS = 10 (1024-entry top level) */
	store_pte(&proc_tbl[2 * 1], (unsigned long) pgdir | 10);
	do_tlbie(0xc00, 0);	/* invalidate all TLB entries */
}

static unsigned long *read_pgd(unsigned long i)
{
	unsigned long ret;

	__asm__ volatile("ldbrx %0,%1,%2" : "=r" (ret) : "b" (pgdir),
			 "r" (i * sizeof(unsigned long)));
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
	__asm__ volatile("ptesync" ::: "memory");
	eas_mapped[neas_mapped++] = ea;
}

void unmap(void *ea)
{
	unsigned long epn = (unsigned long) ea >> 12;
	unsigned long i, j;
	unsigned long *ptep;

	i = (epn >> 9) & 0x3ff;
	j = epn & 0x1ff;
	if (pgdir[i] == 0)
		return;
	ptep = read_pgd(i);
	ptep[j] = 0;
	__asm__ volatile("ptesync" ::: "memory");
	do_tlbie(((unsigned long)ea & ~0xfff), 0);
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
	if (test_exec(0, ptr, MSR_SF | MSR_IR | MSR_LE))
		return 1;
	/* SRR0 and SRR1 should be set correctly */
	if (mfspr(SRR0) != (long) ptr ||
	    mfspr(SRR1) != (MSR_SF | 0x40000000 | MSR_IR | MSR_LE))
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
	if (!test_exec(0, ptr, MSR_SF | MSR_IR | MSR_LE))
		return 1;
	/* create a second PTE */
	map((void *)ptr2, (void *)mem, PERM_EX | REF);
	/* this should succeed and be a cache hit */
	if (!test_exec(0, ptr2, MSR_SF | MSR_IR | MSR_LE))
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
	if (!test_exec(1, ptr, MSR_SF | MSR_IR | MSR_LE))
		return 1;
	/* invalidate the PTE */
	unmap((void *)ptr);
	/* install a second PTE */
	map((void *)ptr2, (void *)mem, PERM_EX | REF);
	/* this should fail */
	if (test_exec(1, ptr, MSR_SF | MSR_IR | MSR_LE))
		return 2;
	/* SRR0 and SRR1 should be set correctly */
	if (mfspr(SRR0) != (long) ptr ||
	    mfspr(SRR1) != (MSR_SF | 0x40000000 | MSR_IR | MSR_LE))
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
	if (test_exec(2, ptr, MSR_SF | MSR_IR | MSR_LE))
		return 1;
	/* SRR0 and SRR1 should be set correctly */
	if (mfspr(SRR0) != ptr2 ||
	    mfspr(SRR1) != (MSR_SF | 0x40000000 | MSR_IR | MSR_LE))
		return 2;
	/* create a PTE for the second page */
	map((void *)ptr2, (void *)mem2, PERM_EX | REF);
	/* this should succeed */
	if (!test_exec(2, ptr, MSR_SF | MSR_IR | MSR_LE))
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
	if (test_exec(0, ptr, MSR_SF | MSR_IR | MSR_LE))
		return 1;
	/* SRR0 and SRR1 should be set correctly */
	if (mfspr(SRR0) != ptr ||
	    mfspr(SRR1) != (MSR_SF | 0x10000000 | MSR_IR | MSR_LE))
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
	if (test_exec(2, ptr, MSR_SF | MSR_IR | MSR_LE))
		return 1;
	/* SRR0 and SRR1 should be set correctly */
	if (mfspr(SRR0) != ptr2 ||
	    mfspr(SRR1) != (MSR_SF | 0x10000000 | MSR_IR | MSR_LE))
		return 2;
	/* create a PTE for the second page with execute permission */
	map((void *)ptr2, (void *)mem2, PERM_RD | PERM_EX | REF);
	/* this should succeed */
	if (!test_exec(2, ptr, MSR_SF | MSR_IR | MSR_LE))
		return 3;
	return 0;
}

int mmu_test_17(void)
{
	unsigned long mem = 0x1000;
	unsigned long ptr = 0x349000;

	/* create a PTE without the ref bit set */
	map((void *)ptr, (void *)mem, PERM_EX);
	/* this should fail */
	if (test_exec(2, ptr, MSR_SF | MSR_IR | MSR_LE))
		return 1;
	/* SRR0 and SRR1 should be set correctly */
	if (mfspr(SRR0) != (long) ptr ||
	    mfspr(SRR1) != (MSR_SF | 0x00040000 | MSR_IR | MSR_LE))
		return 2;
	/* create a PTE without ref or execute permission */
	unmap((void *)ptr);
	map((void *)ptr, (void *)mem, 0);
	/* this should fail */
	if (test_exec(2, ptr, MSR_SF | MSR_IR | MSR_LE))
		return 1;
	/* SRR0 and SRR1 should be set correctly */
	/* RC update fail bit should not be set */
	if (mfspr(SRR0) != (long) ptr ||
	    mfspr(SRR1) != (MSR_SF | 0x10000000 | MSR_IR | MSR_LE))
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
	/* console_init(); */
	init_mmu();

	do_test(1, mmu_test_1);
	do_test(2, mmu_test_2);
	do_test(3, mmu_test_3);
	do_test(4, mmu_test_4);
	do_test(5, mmu_test_5);
	do_test(6, mmu_test_6);
	do_test(7, mmu_test_7);
	do_test(8, mmu_test_8);
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

	return fail;
}
