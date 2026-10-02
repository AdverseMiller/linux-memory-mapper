# Path to the Linux kernel source directory
KDIR ?= /lib/modules/$(shell uname -r)/build

.PHONY: all clean
all:
	$(MAKE) -C $(KDIR) M=$(CURDIR)/src modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR)/src clean
	if [ -f src/tests/Makefile ]; then $(MAKE) -C src/tests KDIR=$(KDIR) clean; fi
