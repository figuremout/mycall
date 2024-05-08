# AIM
Add a syscall to read process info into buffer.

In order to add a self-defined syscall, here is two ways:
- Insert a module.
- Patch the kernel.

**CAUTION: NO SAFETY GUARANTEED**

Test it in a Virtual Machine.

```
|- mycall.h	# Macros and Struct Definition
|- mycall.patch	# Patch for the kernel
|- mymod.c	# Module Implementation
|- myps.c	# My version of ps/pstree commands for testing my syscall
```

# Insert a module
Tested on ubuntu 20.04 amd64 (**5.15.0-105-generic**).

1. Make sure headers installed
2. Compile
```bash
$ make

# or with clangd
$ bear -- make
```

3. Insert module
```bash
$ sudo insmod mymod.ko MYCALL_NUM=335
```

4. Test with my ps/pstree command.
```bash
$ ./ps
$ ./pstree
```

# Patch the kernel
Tested with kernel **linux-5.15.157**.

1. Patch (with syscall number 335 in the patch file)
```bash
$ cd /usr/src/linux/
$ sudo patch -p1 < mycall.patch
```

2. Build the kernel
```bash
$ sudo make -j$(nproc)
```

3. Install the kernel and reboot
```bash
$ sudo make modules_install install
$ shutdown -r now
```

4. Test with my ps/pstree command.
```bash
$ ./ps -n 335
$ ./pstree -n 335
```
