// vim: noexpandtab:ts=8:sw=8

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "console.h"

/* Helpers */
#define PPC_BIT(x)	(0x8000000000000000ul >> (x))

#define XSTR(x)		#x
#define STR(x)		XSTR(x)

/* MSR definitions */
#define MSR_LE		0x1
#define MSR_DR		0x10
#define MSR_IR		0x20
#define MSR_HV		0x1000000000000000ul
#define MSR_SF		0x8000000000000000ul

static uint64_t msr_dflt;
#define MSR_DFLT	msr_dflt

/* SPRs */
#define DSISR		18
#define DAR		19
#define SRR0		26
#define SRR1		27
#define PIDR		48

#define LPCR		318
#define LPCR_UPRT	PPC_BIT(41)
#define LPCR_HR		PPC_BIT(43)

#define PTCR		464

/* Partition defs */
#define PATE_HR		PPC_BIT(0)

/* Radix PTE */
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
 * Minimum VA/PA addresses to use in tests, to avoid overwriting code
 * or data areas.
 */
#define MIN_VA		0x4000000
#define MIN_PA		0x4000000
#define VA(v)		(MIN_VA + (v))
#define PA(p)		(MIN_PA + (p))

/*
 * P9 MMU config
 *
 * Radix tree levels for 4k pages:
 *      sizes: 64 KB | 4 KB | 4 KB | 4 KB
 *   #entries:  8192 |  512 |  512 |   512
 * Radix tree levels for 64k pages:
 *      sizes: 64 KB | 4 KB | 4 KB | 256 B
 *   #entries:  8192 |  512 |  512 |    32
 */

/* Config 4K/64K pages */
#define PAGE_SHIFT	16

#define L3_NLS		(9 - (PAGE_SHIFT - 12))
#define L4_INDEX_MASK	((1 << L3_NLS) -1)
#define L4_ENTRIES	(1ul << L3_NLS)

/* Number of valid bits in PID */
#define PIDR_BITS	20
/* Root Page Dir */
#define RPD_ENTRIES	8192
/* Root Page Dir Size */
#define RPDS		13	/* 2^13 = 8192 entries */
/* Radix Tree Size */
#define RTS1		2UL
#define RTS2		5UL	/* 0b10101 = 0x15 = 21 = 2^(21+31) = 2^52 */

/* Partition Table size */
#define PATS		4	/* 2^(12+4) = 64K */
#define PARTTAB_SIZE	0x10000

/*
 * Partition Page Dir (PPD)
 *
 * Use 1G large pages in the PPD.
 */
#define PPD_ADDR_BITS	52
#define PPD_L1_BITS	13
#define PPD_L2_BITS	9
#define PPD_PA_INC	(1ul << (PPD_ADDR_BITS - (PPD_L1_BITS + PPD_L2_BITS)))

/* Process Table size */
#define PROCTAB_SIZE_SHIFT 12	/* 2^(12 + 12) = 16M */

/* Table addresses */
#define PGDIR_ADDR	0x0010000	/* 64K - 8192-entries */
/* Process table ((1 << PIDR_BITS) * 16 = 16M = 0x1000000) */
#define PROCTAB_ADDR	0x1000000	/* 16M - 1048576 entries */
#define PARTTAB_ADDR	0x2000000	/* 64K */
#define PARTPGDIR_ADDR	0x2010000	/* 64K */
#define FREEPTR_ADDR	0x2020000

/* Common MMU defs */
#define PID		1ul

#define CACHE_LINE_SIZE	64

#define RTS		((RTS1 << 61) | (RTS2 << 5))

#define PAGE_SIZE	(1ul << PAGE_SHIFT)
#define PAGE_MASK	(PAGE_SIZE - 1)

/* TLB definitions */

#if PAGE_SHIFT == 12	/* 4K */
#define AP		0
#else			/* 64K */
#define AP		(5ul << 5)
#endif

#define RIC_TLB		0
#define RIC_PWC		1
#define RIC_ALL		2

#define PRS		1

#define IS(x)		((unsigned long)(x) << 10)
#define IS_VA		IS(0)
#define IS_PID		IS(1)
#define IS_LPID		IS(2)
#define IS_ALL		IS(3)

#define TLBIE_5(rb, rs, ric, prs, r)			\
	__asm__ volatile(".long 0x7c000264 | "		\
		"%0 << 21 | "				\
		STR(ric) " << 18 | "			\
		STR(prs) " << 17 | "			\
		STR(r) "<< 16 | "			\
		"%1 << 11"				\
		: : "r" (rs), "r" (rb) : "memory")

/* Global data */

/* Root Page Dir */
unsigned long *pgdir =		(unsigned long *) PGDIR_ADDR;
unsigned long *proc_tbl =	(unsigned long *) PROCTAB_ADDR;
unsigned long *part_tbl =	(unsigned long *) PARTTAB_ADDR;
unsigned long *part_pgdir =	(unsigned long *) PARTPGDIR_ADDR;
unsigned long free_ptr =			  FREEPTR_ADDR;

/* Prototypes */

extern void register_process_table(unsigned long proc_tbl, unsigned long ptbs);

/* Functions */

/* Print functions */

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

#define ABS(x)		((x) < 0 ? -(x) : (x))

void print_dec(long l)
{
	char buf[32], *p;
	char minus;
	long r;

	if (l == 0) {
		putchar('0');
		return;
	}

	p = &buf[31];
	*p-- = 0;
	minus = l < 0;

	/* build output string from right to left */
	do {
		r = l % 10;
		l = l / 10;
		*p-- = ABS(r) + '0';
	} while (l != 0);

	/* print string */
	if (minus)
		putchar('-');
	while (*++p)
		putchar(*p);
}

// i < 100
void print_test_number(int i)
{
	print_string("test ");
	putchar(48 + i/10);
	putchar(48 + i%10);
	putchar(':');
}

/* Helper functions */

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

/* Special registers access functions */

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

static inline unsigned long mftb(void)
{
	unsigned long ret;

	__asm__ volatile("mftb %0" : "=r"(ret));
	return ret;
}

static inline void mb(void)
{
	__asm__ volatile("sync" : : : "memory");
}

/* TLB functions */

static inline void tlbie_all(int prs)
{
	if (prs)
		TLBIE_5(IS_ALL, 0, RIC_ALL, 1, 1);
	else
		TLBIE_5(IS_ALL, 0, RIC_ALL, 0, 1);
}

static inline void tlbie_va_nosync(unsigned long va, int prs)
{
	va &= ~PAGE_MASK;

	if (prs)
		TLBIE_5(IS_VA | va | AP, PID << 32, RIC_TLB, 1, 1);
	else
		TLBIE_5(IS_VA | va | AP, PID << 32, RIC_TLB, 0, 1);
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

/* Store PTE/table entry */
static inline void store_pte(unsigned long *p, unsigned long pte)
{
#ifdef __LITTLE_ENDIAN__
	__asm__ volatile("stdbrx %1,0,%0" : : "r" (p), "r" (pte) : "memory");
#else
	__asm__ volatile("stdx   %1,0,%0" : : "r" (p), "r" (pte) : "memory");
#endif
	__asm__ volatile("ptesync" : : : "memory");
}

/* MMU initialization functions */

void init_process_table(void)
{
	zero_memory(proc_tbl, (1UL << PIDR_BITS) * sizeof(unsigned long) * 2);
	zero_memory(pgdir, RPD_ENTRIES * sizeof(unsigned long));

	/*
	 * Set up proctab entries 0 and 1 identically,
	 * to be able to run tests with PID=0 or PID=1.
	 */
	store_pte(&proc_tbl[0], RTS | (unsigned long) pgdir | RPDS);
	store_pte(&proc_tbl[2], RTS | (unsigned long) pgdir | RPDS);
}

void init_partition_table(void)
{
	unsigned long pa, pte, *ptep;

	/* Select Radix MMU (HR), with HW process table */
	mtspr(LPCR, mfspr(LPCR) | LPCR_UPRT | LPCR_HR);

	/*
	 * Set up partition page dir, needed to translate process table
	 * addresses.
	 * Map 2GB 1-1, with large pages.
	 */
	zero_memory(part_tbl, PARTTAB_SIZE);
	store_pte(&part_tbl[0], PATE_HR | RTS | (unsigned long) part_pgdir |
			RPDS);

	/* L1 PTE */
	zero_memory((void *)free_ptr, 512 * sizeof(unsigned long));
	pte = RPTE_V | free_ptr | 9;
	ptep = (unsigned long *)free_ptr;
	free_ptr += 512 * sizeof(unsigned long);
	store_pte(&part_pgdir[0], pte);

	/* L2 PTEs */
	pa = 0;
	pte = RPTE_V | RPTE_L | RPTE_PERM_ALL;
	store_pte(ptep++, pte | (pa & RPTE_RPN_MASK));
	pa += PPD_PA_INC;
	store_pte(ptep++, pte | (pa & RPTE_RPN_MASK));

	store_pte(&part_tbl[1], (unsigned long)proc_tbl);
	mtspr(PTCR, (unsigned long)part_tbl | PATS);
}

void init_mmu(void)
{
	bool hv;

	msr_dflt = mfmsr() | MSR_SF;
	mtmsrd(msr_dflt);
	hv = !!(mfmsr() & MSR_HV);

	init_process_table();

	if (hv) {
		init_partition_table();
		mtspr(PIDR, PID);
		tlbie_all(0);
	} else {
		register_process_table((unsigned long)proc_tbl, PROCTAB_SIZE_SHIFT);
		mtspr(PIDR, PID);
		tlbie_all(PRS);
	}
}

/* Page Table manipulation functions */

static unsigned long *read_pgd(unsigned long i, unsigned long *pgd)
{
	unsigned long ret;

#ifdef __LITTLE_ENDIAN__
	__asm__ volatile("ldbrx %0,%1,%2" : "=r" (ret) : "b" (pgd),
			 "r" (i * sizeof(unsigned long)));
#else
	__asm__ volatile("ldx   %0,%1,%2" : "=r" (ret) : "b" (pgd),
			 "r" (i * sizeof(unsigned long)));
#endif
	return (unsigned long *) (ret & 0x00ffffffffffff00);
}

void map(void *ea, void *pa, unsigned long perm_attr)
{
	unsigned long eaddr = (unsigned long) ea;
	unsigned long pfn = (unsigned long) pa & ~PAGE_MASK;
	unsigned long i;
	unsigned long *ptep;
	unsigned long offset = 52;

	/* level 1 - 13 bits */
	offset -= 13;
	i = (eaddr >> offset) & 0x1fff;
	if (pgdir[i] == 0) {
		zero_memory((void *)free_ptr, 512 * sizeof(unsigned long));
		store_pte(&pgdir[i], RPTE_V | free_ptr | 9);
		free_ptr += 512 * sizeof(unsigned long);
	}
	ptep = read_pgd(i, pgdir);

	/* level 2 - 9 bits */
	offset -= 9;
	i = (eaddr >> offset) & 0x1ff;
	if (ptep[i] == 0){
		zero_memory((void *)free_ptr, 512 * sizeof(unsigned long));
		store_pte(&ptep[i], RPTE_V | free_ptr | 9);
		free_ptr += 512 * sizeof(unsigned long);
	}
	ptep = read_pgd(i, ptep);

	/* level 3 - 9 bits */
	offset -= 9;
	i = (eaddr >> offset) & 0x1ff;
	if (ptep[i] == 0){
		zero_memory((void *)free_ptr, L4_ENTRIES * sizeof(unsigned long));
		store_pte(&ptep[i], RPTE_V | free_ptr | L3_NLS);
		free_ptr += L4_ENTRIES * sizeof(unsigned long);
	}
	ptep = read_pgd(i, ptep);

	/* level 4 - 9/5 bits */
	offset -= L3_NLS;
	i = (eaddr >> offset) & L4_INDEX_MASK;
	store_pte(&ptep[i], RPTE_V | RPTE_L |
		(pfn & 0x00fffffffffff000) | perm_attr);
}

static void unmap_noinval(void *ea)
{
	unsigned long eaddr = (unsigned long) ea;
	unsigned long i;
	unsigned long *ptep;
	unsigned long offset = 52;

	/* level 1 - 13 bits */
	offset -= 13;
	i = (eaddr >> offset) & 0x1fff;
	if (pgdir[i] == 0)
		return;
	ptep = read_pgd(i, pgdir);

	/* level 2 - 9 bits */
	offset -= 9;
	i = (eaddr >> offset) & 0x1ff;
	if (ptep[i] == 0)
		return;
	ptep = read_pgd(i, ptep);

	/* level 3 - 9 bits */
	offset -= 9;
	i = (eaddr >> offset) & 0x1ff;
	if (ptep[i] == 0)
		return;
	ptep = read_pgd(i, ptep);

	/* level 4 - 9/5 bits */
	offset -= L3_NLS;
	i = (eaddr >> offset) & L4_INDEX_MASK;
	store_pte(&ptep[i], 0);
}

void unmap(void *ea)
{
	unmap_noinval(ea);
	tlbie_va((unsigned long)ea, PRS);
}

static void identity_map_256M(void)
{
	long ea, pa;

	for (ea = pa = 0; ea < 256 * 1024 * 1024;
			ea += PAGE_SIZE, pa += PAGE_SIZE)
		map((void *)ea, (void *)pa, DFLT_PERM | PERM_EX);
}

static void mmu_enable(void)
{
	mtmsrd(msr_dflt | MSR_IR | MSR_DR);
}

static unsigned long b1[1024];
static unsigned long b2[1024];

long xor_8regs_2(unsigned long bytes,
	unsigned long * __restrict p1,
	const unsigned long * __restrict p2)
{
	long lines = bytes / (sizeof (long)) / 8;

	do {
		p1[0] ^= p2[0];
		p1[1] ^= p2[1];
		p1[2] ^= p2[2];
		p1[3] ^= p2[3];
		p1[4] ^= p2[4];
		p1[5] ^= p2[5];
		p1[6] ^= p2[6];
		p1[7] ^= p2[7];
		p1 += 8;
		p2 += 8;
	} while (--lines > 0);
	return 0;
}

/* Use more loads than stores */
long xor2(unsigned long bytes,
	unsigned long * __restrict p1,
	const unsigned long * __restrict p2)
{
	long lines = bytes / (sizeof (long)) / 8;

	do {
		p1[0] ^= p2[0] ^ p2[1] ^ p2[2] ^ p2[3] ^ p2[4] ^ p2[5] ^ p2[6] ^ p2[7];
		p1 += 8;
		p2 += 8;
	} while (--lines > 0);
	return 0;
}

/* Use more stores than loads */
long xor3(unsigned long bytes,
	unsigned long * __restrict p1,
	const unsigned long * __restrict p2)
{
	long lines = bytes / (sizeof (long)) / 8;

	do {
		p1[0] ^= p2[0];
		p1[1] ^= p2[0];
		p1[2] ^= p2[0];
		p1[3] ^= p2[0];
		p1[4] ^= p2[0];
		p1[5] ^= p2[0];
		p1[6] ^= p2[0];
		p1[7] ^= p2[0];
		p1 += 8;
		p2 += 8;
	} while (--lines > 0);
	return 0;
}

/* Load test */
long load(unsigned long bytes,
	unsigned long * __restrict p1,
	const unsigned long * __restrict p2)
{
	int i;
	long sum = 0;

	for (i = 0; i < 1024; i+= 4)
		sum += p2[i] + p2[i + 1] + p2[i + 2] + p2[i + 3];
	return sum;
}

/* Store test */
long store(unsigned long bytes,
	unsigned long * __restrict p1,
	const unsigned long * __restrict p2)
{
	int i;

	for (i = 0; i < 1024; i+= 4) {
		p1[i] = i;
		p1[i + 1] = i;
		p1[i + 2] = i;
		p1[i + 3] = i;
	}
	return 0;
}

#define BENCH_SIZE	4096
#define REPS		800U

/* profile benchmark 1 time */
long perf1(long (*func)(unsigned long bytes,
	unsigned long * __restrict p1,
	const unsigned long * __restrict p2))
{
	int i, j;
	long min, start, diff, sum = 0;

	min = 0x7fffffff;
	for (i = 0; i < 3; i++) {
		start = mftb();
		for (j = 0; j < REPS; j++) {
			mb(); /* prevent loop optimization */
			sum += func(BENCH_SIZE, b1, b2);
			mb();
		}
		diff = (long)mftb() - start;
		if (diff < min)
			min = diff;
	}

	if (!min && sum == 0)
		min = 1;

	/*
	print_string("time: ");
	print_dec(min);
	putchar('\n');
	*/

	return min;
}

#define PERF(f)		perf(#f, f)

/* Run benchmark 10 times and print the average time */
long perf(const char *str,
	long (*func)(unsigned long bytes,
		unsigned long * __restrict p1,
		const unsigned long * __restrict p2))
{
	int i;
	long sum;

	sum = 0;
	for (i = 0; i < 10; i++)
		sum += perf1(func);
	print_string(str);
	print_string(": avg: ");
	print_dec(sum / 10);
	putchar('\n');
	return 0;
}

int main(void)
{
	console_init();
	init_mmu();

	/* Map first 256M 1-1 and enable inst/data relocation */
	identity_map_256M();
	mmu_enable();

	print_string("perf test\n");

	PERF(load);
	PERF(store);

	return 0;
}
