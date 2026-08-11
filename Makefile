# Unified Firewall — top-level build orchestration.
#
# Cargo builds the Rust half. The kernel modules build through their platforms'
# own systems, because a hand-rolled compile line works right up until the
# kernel is built with a flag you did not copy, and then it produces a module
# that loads and misbehaves.
#
# The one thing this file does that the sub-builds cannot: `make generate`,
# which compiles a policy into the per-platform artifacts all three kernel
# builds consume. Run it before building any kernel component.
#
#   make                 build the Rust workspace (zero dependencies)
#   make tls             build with TLS termination (pulls rustls)
#   make generate        compile POLICY into build/generated/{windows,linux,macos}
#   make test            the full Rust test suite
#   make check           test + fmt + the ABI drift checks
#   make kernel-linux    the module and the eBPF programs (Linux only)
#   make kernel-windows  the WFP driver (Windows, needs the WDK)
#   make kernel-macos    the Network Extension (macOS, needs Xcode)
#   make install         install the daemon and CLI for the host platform
#   make clean

CARGO ?= cargo
POLICY ?= policies/base/default_deny.yaml
GENERATED := build/generated
PREFIX ?= /usr/local

# Detected rather than configured: every target below that cares is only
# buildable on one platform anyway, and asking the operator to state which
# machine they are on is a question the machine can answer.
UNAME := $(shell uname -s 2>/dev/null || echo Windows)
ifeq ($(UNAME),Linux)
    HOST_PLATFORM := linux
else ifeq ($(UNAME),Darwin)
    HOST_PLATFORM := macos
else
    HOST_PLATFORM := windows
endif

.PHONY: all build tls test check fmt clippy generate clean install uninstall \
        kernel kernel-linux kernel-windows kernel-macos \
        docker-test policies help

all: build

help:
	@sed -n '1,20p' $(firstword $(MAKEFILE_LIST))

# --- Rust ---------------------------------------------------------------

build:
	$(CARGO) build --workspace --release

# TLS is a build-time opt-in rather than a default, because the alternative to
# a vetted TLS library is a hand-written one, and hand-rolled crypto in a
# security product is strictly worse than no TLS at all. An operator who needs
# the management API on a routable address accepts rustls and its tree; one who
# terminates at a proxy or stays on loopback pays nothing.
#
# A binary built without this refuses to start when the configuration asks for
# TLS, rather than serving plaintext on a port configured as encrypted.
tls:
	$(CARGO) build --workspace --release --features ufw-daemon/tls

test:
	$(CARGO) test --workspace

# What CI runs. `test` alone would miss the two things most likely to break
# silently: the generated C headers drifting from the kernel's own structures,
# and the shipped example policies no longer compiling.
check: test
	$(CARGO) fmt --all -- --check
	$(CARGO) test --workspace --test kernel_abi_tests
	# The TLS feature changes which code compiles, so it needs its own run.
	# A cfg-gated path that only builds in one configuration is a path that
	# breaks in the other without anyone noticing until a release.
	$(CARGO) test -p ufw-daemon --features tls
	$(MAKE) policies

fmt:
	$(CARGO) fmt --all

clippy:
	$(CARGO) clippy --workspace --all-targets -- -D warnings

# Every shipped policy must compile, cleanly, with the backends in agreement.
# If they do not, the documentation is wrong and the examples are a trap.
policies: build
	@failed=0; \
	for f in $$(find policies tests/docker -name '*.yaml' -not -path '*/fragments/*'); do \
		if ! ./target/release/ufwctl policy validate "$$f" >/dev/null 2>&1; then \
			echo "FAIL $$f"; \
			./target/release/ufwctl policy validate "$$f" 2>&1 | head -20; \
			failed=1; \
		else \
			echo "ok   $$f"; \
		fi; \
	done; \
	exit $$failed

# --- policy generation --------------------------------------------------

# The kernel builds consume these. The Network Extension *requires* them —
# unlike the two kernel modules it compiles its policy in, because it starts
# enforcing before the daemon connects and so needs a rule table at build time.
generate: build
	@mkdir -p $(GENERATED)
	./target/release/ufwctl policy compile $(POLICY) --out $(GENERATED)
	@echo
	@echo "Generated from $(POLICY) into $(GENERATED)/"

# --- kernel modules -----------------------------------------------------

kernel: kernel-$(HOST_PLATFORM)

kernel-linux: generate
	$(MAKE) -C kernel/linux

kernel-windows: generate
	$(MAKE) -C kernel/windows

kernel-macos: generate
	$(MAKE) -C kernel/macos

# --- containerised tests ------------------------------------------------

# The `build` profile compiles the kernel C and the eBPF programs; `verify`
# additionally runs the real eBPF verifier, which needs privileges. See
# tests/docker/docker-compose.yml for why they are separate.
docker-test:
	docker compose -f tests/docker/docker-compose.yml --profile verify up \
		--abort-on-container-exit --exit-code-from build

# --- install ------------------------------------------------------------

install: build
	install -d $(DESTDIR)$(PREFIX)/sbin $(DESTDIR)$(PREFIX)/bin
	install -m 0755 target/release/ufwd $(DESTDIR)$(PREFIX)/sbin/ufwd
	install -m 0755 target/release/ufwctl $(DESTDIR)$(PREFIX)/bin/ufwctl
ifeq ($(HOST_PLATFORM),linux)
	install -m 0755 target/release/ufw-nft $(DESTDIR)$(PREFIX)/bin/ufw-nft
	install -m 0755 build/linux/firewall.sh $(DESTDIR)$(PREFIX)/bin/firewall
endif
	install -d $(DESTDIR)/etc/unified-firewall/policies
	install -d $(DESTDIR)/etc/unified-firewall/sig-rules
	cp -R sig-rules/* $(DESTDIR)/etc/unified-firewall/sig-rules/
	cp -R policies/* $(DESTDIR)/etc/unified-firewall/policies/
	@echo
	@echo "Installed the daemon and CLI. The kernel module is a separate step:"
	@echo "  make kernel-$(HOST_PLATFORM)"
	@echo
	@echo "No policy was ACTIVATED. The shipped policies are in"
	@echo "/etc/unified-firewall/policies; choose one deliberately —"
	@echo "policies/base/default_deny.yaml enforces from the first packet, and"
	@echo "policies/base/default_allow.yaml is the rollout phase that comes"
	@echo "before it. On Linux, \`firewall apply default_allow\` starts real"
	@echo "nftables enforcement and \`firewall\` opens the live dashboard."

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/sbin/ufwd $(DESTDIR)$(PREFIX)/bin/ufwctl \
	      $(DESTDIR)$(PREFIX)/bin/ufw-nft $(DESTDIR)$(PREFIX)/bin/firewall
	@echo "Left /etc/unified-firewall in place: it holds policy you wrote."

clean:
	$(CARGO) clean
	rm -rf $(GENERATED)
	-$(MAKE) -C kernel/linux clean 2>/dev/null
