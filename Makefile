CC		:= gcc
CFLAGS		:= -Wall -std=gnu99 # c99
obj-m		:= mymod.o
CURRENT_PATH	:= $(shell pwd)
LINUX_KERNEL	:= $(shell uname -r)
LINUX_KERNEL_PATH:=/usr/src/linux-headers-$(LINUX_KERNEL)

.PHONY: all
all: mymod.ko ps pstree

.PHONY: clean
clean:
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) clean
	rm -rf ./ps
	rm -rf ./pstree

mymod.ko: mymod.c
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) modules

ps: myps.c
	$(CC) $(CFLAGS) -o $@ $<

pstree: myps.c
	$(CC) $(CFLAGS) -DPSTREE -o $@ $<
