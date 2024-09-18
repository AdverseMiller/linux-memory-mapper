obj-m += main.o

# Path to the Linux kernel source directory
KDIR := /lib/modules/$(shell uname -r)/build

# Current directory
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
vm:
	$(MAKE) -C /lib/modules/6.10.7-arch1-1/build  M=$(PWD) modules