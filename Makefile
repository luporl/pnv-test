# XICS not supported

SHELL := bash

SUBDIRS := decrementer spr_read  modes sc reservation trace fpu privileged mmu misc illegal alignment perf
TARGETS := all check

.PHONY: $(TARGETS) $(SUBDIRS)

$(TARGETS): $(SUBDIRS)

$(SUBDIRS):
	make -C $@ $(MAKECMDGOALS)  

big:
	make BIG=1

clean:
	$(RM) $(SUBDIRS:%=%/*.{o,elf,bin})
