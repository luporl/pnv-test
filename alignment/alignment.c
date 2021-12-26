#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "console.h"

#define TEST "Test "
#define PASS "PASS\n"
#define FAIL "FAIL\n"

extern int align_test_le(unsigned long *);
extern int align_test_le_move_assist_0(unsigned long *);
extern int align_test_atomic(unsigned long *);
extern int align_test_indexed(unsigned long *);
extern int align_test_prefixed(unsigned long *);

/*
 * Mostly so we have an address to point to. The instructions should
 * cause an exception before even accessing it.
 */
static unsigned long test_data[] = {
	0xdeadbeef,
	0xdeadbabe,
	0x2badd00d,
	0x3dc0ffee,
};

// i < 100
void print_test_number(int i)
{
	puts(TEST);
	putchar(48 + i/10);
	putchar(48 + i%10);
	putchar(':');
}

int main(void)
{
	int fail = 0;

	console_init();

	print_test_number(1);
	if (align_test_le(test_data)) {
		fail = 1;
		puts(FAIL);
	} else {
		puts(PASS);
	}

	print_test_number(2);
	if (align_test_le_move_assist_0(test_data)) {
		fail = 1;
		puts(FAIL);
	} else {
		puts(PASS);
	}

	print_test_number(3);
	if (align_test_atomic(test_data)) {
		fail = 1;
		puts(FAIL);
	} else {
		puts(PASS);
	}

	print_test_number(4);
	if (align_test_indexed(test_data)) {
		fail = 1;
		puts(FAIL);
	} else {
		puts(PASS);
	}

	print_test_number(5);
	if (align_test_prefixed(test_data)) {
		fail = 1;
		puts(FAIL);
	} else {
		puts(PASS);
	}

	return fail;
}
