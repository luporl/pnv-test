# pnv-test

Lowlevel tests for the QEMU PowerNV machines. These are the Microwatt
tests adapted to use a PowerNV console.

To run under QEMU, you will need to add an extra machine option to
start the CPU in Little Endian.

## Building

make

## Run

For all tests, simply run :

```
 $(QEMU) -M powernv9,endianness=little -bios ./test/test.bin -serial mon:stdio -nographic
```
