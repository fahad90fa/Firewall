# Unified Firewall — eBPF programs.
#
# Separate from the parent Makefile because this is a different toolchain
# targeting a different machine. The kernel module is built by the kernel's own
# build system with the kernel's flags; these are compiled by clang for the bpf
# target, verified by the kernel at load time rather than at link time, and
# subject to constraints — bounded loops, no function pointers, an instruction
# budget — that no C compiler will tell you about.
#
# The parent Makefile delegates here. Building from this directory directly is
# also fine and is what you want while iterating on a verifier rejection.
#
# Targets:
#   make            build all three objects
#   make verify     load each through the real verifier, then unload
#   make dump       disassemble, for reading what the verifier actually saw
#   make clean

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool

# The verifier's view of the machine. Deriving it rather than hard-coding x86
# means an arm64 build does not silently produce a program with the wrong
# field offsets.
ARCH := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/; s/armv7l/arm/')

# Where `make generate` in the repository root writes the compiled policy.
GENERATED ?= ../../../build/generated/linux

# -O2 is not optional. The verifier rejects unoptimised output, because the
# patterns it needs to see — bounded loops unrolled, bounds checks hoisted to
# where it can prove them — only exist after optimisation. A -O0 build fails
# with a verifier error that says nothing about optimisation.
#
# -g keeps BTF, which CO-RE needs to relocate field offsets against the running
# kernel rather than the one this was compiled against.
# Debian and Ubuntu put `asm/types.h` under a multiarch directory, and
# <linux/bpf.h> includes it transitively. Without this the build fails on
# exactly the distributions docs/development/setup.md tells you to use, with an
# error that names a header nobody wrote. Harmless where the path does not
# exist.
MULTIARCH := $(shell $(CC) -print-multiarch 2>/dev/null)
ifneq ($(MULTIARCH),)
INCLUDES += -I/usr/include/$(MULTIARCH)
endif

CFLAGS := -O2 -g -Wall -Werror \
	-target bpf \
	-D__TARGET_ARCH_$(ARCH) \
	-I. -I$(GENERATED) $(INCLUDES)

SRCS := packet_filter.c conntrack.c metering.c xdp_filter.c identity_lsm.c
OBJS := $(SRCS:.c=.o)

.PHONY: all verify dump clean generated

all: $(OBJS)

# packet_filter.c includes the generated rule table; the other two do not.
packet_filter.o: packet_filter.c common.h generated
	$(CLANG) $(CFLAGS) -c $< -o $@

%.o: %.c common.h
	$(CLANG) $(CFLAGS) -c $< -o $@

generated:
	@if [ ! -f "$(GENERATED)/ufw_ebpf_rules.h" ]; then \
		echo "error: $(GENERATED)/ufw_ebpf_rules.h not found."; \
		echo "       The fast path compiles the rule table in — it has no"; \
		echo "       runtime channel to receive one. Run 'make generate' in the"; \
		echo "       repository root first."; \
		exit 1; \
	fi

# Run the real verifier.
#
# This is the check worth having and the one a compile cannot give you. A
# program that builds cleanly can still be rejected at load time for exceeding
# the instruction budget or for a bounds check the verifier cannot follow — and
# finding that out here costs seconds instead of an incident.
#
# Needs root and a mounted bpffs.
verify: all
	@for obj in $(OBJS); do \
		printf '%-24s' "$$obj"; \
		if $(BPFTOOL) prog load $$obj /sys/fs/bpf/ufw_verify_check 2>/tmp/ufw_verify.log; then \
			echo "ok"; \
			rm -f /sys/fs/bpf/ufw_verify_check; \
		else \
			echo "REJECTED"; \
			echo "--- verifier output ---"; \
			cat /tmp/ufw_verify.log; \
			rm -f /sys/fs/bpf/ufw_verify_check; \
			exit 1; \
		fi; \
	done

# What the verifier actually sees, which is not what you wrote: the unrolled
# loops and hoisted bounds checks are the whole reason a rejection can be hard
# to read from the source alone.
dump: all
	@for obj in $(OBJS); do \
		echo "=== $$obj ==="; \
		$(LLVM_OBJDUMP) -d $$obj 2>/dev/null || llvm-objdump -d $$obj; \
	done

clean:
	rm -f $(OBJS)
