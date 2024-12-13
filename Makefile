# required for module and clean targets
KERNEL_DIR ?= YOU_NEED_TO_PASS_KERNEL_DIR
# required for install target
SHARED_DIR ?= YOU_NEED_TO_PASS_OUTPUT_DIR

export CROSS_COMPILE ?= aarch64-none-linux-gnu-
export ARCH ?= arm64

# either set COMPILER_DIR manually or make sure the compiler is in PATH
ifneq ($(origin COMPILER_DIR), undefined)
    export PATH := ${COMPILER_DIR}:${PATH}
endif

HEADERS=rsi.h

obj-m += rsi.o

all: module install

module: ${HEADERS}
	make -C ${KERNEL_DIR} M=$(PWD) modules

install:
	install rsi.ko ${OUTPUT_DIR}

clean:
	make -C ${KERNEL_DIR} M=$(PWD) clean
