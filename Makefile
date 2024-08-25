# Makefile for compiling eBPF XDP programs and Loadable Kernel Modules for x86 and AArch64

# Set the kernel source directory
KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build

# Architecture and cross-compilation settings
ARCH ?= x86

# Set target-specific flags
ifeq ($(ARCH),x86)
    TARGET_ARCH := x86
    BPF_CFLAGS += -D__TARGET_ARCH_x86
    CC := clang
    CROSS_COMPILE :=
else ifeq ($(ARCH),arm64)
    TARGET_ARCH := arm64
    BPF_CFLAGS += -D__TARGET_ARCH_arm64
    CC := aarch64-linux-gnu-clang
    CROSS_COMPILE := aarch64-linux-gnu-
else
    $(error Unsupported architecture: $(ARCH))
endif

# Common Clang and LLVM flags
CFLAGS := -O2 -Wall
CFLAGS += -I$(KERNEL_DIR)/include
CFLAGS += -I$(KERNEL_DIR)/include/uapi

BPF_CFLAGS += -D__KERNEL__
BPF_CFLAGS += -I$(KERNEL_DIR)/include
BPF_CFLAGS += -I$(KERNEL_DIR)/include/uapi
BPF_CFLAGS += -I$(KERNEL_DIR)/include/linux
BPF_CFLAGS += -I/usr/include/$(TARGET_ARCH)-linux-gnu

# Source files
XDP_PROG_SRC := $(wildcard *.c)
MODULE_SRC := $(filter-out $(XDP_PROG_SRC), $(wildcard *.c))

# Object files
XDP_PROG_OBJ := $(patsubst %.c,%.o,$(XDP_PROG_SRC))
MODULE_OBJ := $(patsubst %.c,%.o,$(MODULE_SRC))

# Kernel module (.ko) files
MODULE_KO := $(patsubst %.c,%.ko,$(MODULE_SRC))

# Targets

all: $(XDP_PROG_OBJ) $(MODULE_KO)

# Compile the eBPF programs
%.o: %.c
	$(CC) $(BPF_CFLAGS) -target bpf -c $< -o $@

# Compile the kernel modules
$(MODULE_OBJ):
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) ARCH=$(TARGET_ARCH) CROSS_COMPILE=$(CROSS_COMPILE) $(MODULE_OBJ)

# Link the kernel modules
$(MODULE_KO): $(MODULE_OBJ)
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) ARCH=$(TARGET_ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules

# Clean up
clean:
	rm -f $(XDP_PROG_OBJ) $(MODULE_OBJ) $(MODULE_KO)
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) ARCH=$(TARGET_ARCH) CROSS_COMPILE=$(CROSS_COMPILE) clean

.PHONY: all clean

