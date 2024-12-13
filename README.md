# Introduction

This is a custom kernel module to perform CCA RSI operations from user space. It
creates a `/dev/rsi` interface to be used with ioctl commands.

Most of the commands are from RSI specifications, some are Islet extensions.

# Compilation

To compile and install you need 3 things:

1. `KERNEL_DIR`: directory where the kernel for the module build resides
2. `OUTPUT_DIR`: directory where to put the compiled module
3. Compiler: `CROSS_COMPILE` variable. Make sure the compiler is in `PATH` or set
   the `COMPILER_DIR` manually so the Makefile will add it to `PATH`.

# Usage

Those ioctls are best used with higher level code available in the library and
cmdline tool here:

* https://github.com/islet-project/rust-rsi
* https://github.com/islet-project/rsictl
