# Unified Firewall — Linux kernel module and eBPF programs.
#
# The module itself is built by the kernel's build system through Kbuild; this
# file is the wrapper that invokes it, plus the eBPF half, which the kernel
# build knows nothing about.
#
# Targets:
#   make                build the module and the eBPF objects
#   make module         the .ko only
#   make ebpf           the eBPF objects only
#   make install        install the module (needs root)
#   make load / unload  insmod / rmmod, for development
#   make check          sanity checks that do not need a kernel to run
#   make clean

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Where the compiler put the generated headers. `make generate` in the
# repository root produces them; the paths here match its output layout.
GENERATED ?= $(PWD)/../../build/generated/linux

CLANG ?= clang
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')

EBPF_SRC := ebpf/packet_filter.c ebpf/conntrack.c ebpf/metering.c
EBPF_OBJ := $(EBPF_SRC:.c=.o)

# -O2 is not optional for eBPF: the verifier rejects unoptimised output,
# because the patterns it needs to see (bounded loops unrolled, bounds checks
# hoisted) only appear after optimisation. -g keeps BTF, which the loader
# needs for CO-RE.
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
	-I$(PWD)/ebpf -I$(GENERATED) \
	-Wall -Werror -Wno-unused-function

.PHONY: all module ebpf install load unload check clean generated

all: module ebpf

# --- kernel module --------------------------------------------------------

module: generated
	$(MAKE) -C $(KDIR) M=$(PWD) modules

generated:
	@if [ ! -f "$(GENERATED)/ufw_rules.h" ]; then \
		echo "note: $(GENERATED)/ufw_rules.h not found."; \
		echo "      The module does not need it — policy normally arrives"; \
		echo "      over netlink from ufwd. Run 'make generate' in the"; \
		echo "      repository root to bake a policy in instead."; \
	fi

# --- eBPF -----------------------------------------------------------------

ebpf: $(EBPF_OBJ)

# packet_filter.c includes the generated rule table, so it cannot build
# without one. The other two can.
ebpf/packet_filter.o: ebpf/packet_filter.c ebpf/common.h
	@if [ ! -f "$(GENERATED)/ufw_ebpf_rules.h" ]; then \
		echo "error: $(GENERATED)/ufw_ebpf_rules.h is required to build the"; \
		echo "       fast path. Run 'make generate' in the repository root."; \
		exit 1; \
	fi
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

ebpf/%.o: ebpf/%.c ebpf/common.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# --- checks ---------------------------------------------------------------

# Verify the eBPF objects load before anything tries to attach them on a
# production host. `bpftool prog load` runs the real verifier, so this catches
# an instruction-budget overrun at build time rather than at deploy time.
check: ebpf
	@for obj in $(EBPF_OBJ); do \
		echo "verifying $$obj"; \
		$(BPFTOOL) prog load $$obj /sys/fs/bpf/ufw_check 2>&1 && \
			$(BPFTOOL) prog detach pinned /sys/fs/bpf/ufw_check 2>/dev/null; \
		rm -f /sys/fs/bpf/ufw_check; \
	done

# --- install and development ---------------------------------------------

install: module
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a

load: module
	insmod ufw.ko

unload:
	rmmod ufw || true

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f $(EBPF_OBJ)
