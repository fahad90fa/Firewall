# Unified Firewall — Windows callout driver.
#
# Drives MSBuild against the WDK. Run from a Visual Studio developer prompt
# with the WDK installed, or from WSL with `MSBUILD` pointing at msbuild.exe.
#
# Targets:
#   make              build the driver (x64, Debug)
#   make release      build signed-ready release binaries
#   make analyze      Code Analysis (/analyze) — required before release
#   make sdv          Static Driver Verifier — required before release
#   make sign         test-sign for local development
#   make clean
#
# `analyze` and `sdv` are not optional steps that got left in a Makefile. A
# WFP callout runs at DISPATCH_LEVEL on every packet on every processor; the
# class of bug those two tools find (IRQL violations, lock imbalance, unchecked
# allocations) is precisely the class that produces a bugcheck under load on a
# machine you cannot attach a debugger to. `make release` depends on both.

MSBUILD ?= msbuild.exe
PLATFORM ?= x64
CONFIGURATION ?= Debug
PROJECT := ufw.vcxproj

# Where `make generate` in the repository root puts the compiled policy. The
# driver does not need it — policy normally arrives over IOCTL from ufwd — but
# a build can bake one in for an appliance image.
GENERATED ?= ../../build/generated/windows

.PHONY: all release analyze sdv sign clean generated

all: generated
	$(MSBUILD) $(PROJECT) /p:Configuration=$(CONFIGURATION) /p:Platform=$(PLATFORM)

release: analyze sdv
	$(MSBUILD) $(PROJECT) /p:Configuration=Release /p:Platform=$(PLATFORM)

analyze:
	$(MSBUILD) $(PROJECT) /p:Configuration=$(CONFIGURATION) /p:Platform=$(PLATFORM) \
		/p:RunCodeAnalysis=true /p:EnablePREfast=true

# SDV needs a clean build to instrument, hence the explicit clean first.
sdv:
	$(MSBUILD) $(PROJECT) /p:Configuration=Release /p:Platform=$(PLATFORM) /t:Clean
	$(MSBUILD) $(PROJECT) /p:Configuration=Release /p:Platform=$(PLATFORM) \
		/t:sdv /p:Inputs="/check:default.sdv"
	$(MSBUILD) $(PROJECT) /p:Configuration=Release /p:Platform=$(PLATFORM) /t:dvl

# Test signing only. Production signing goes through build/windows/driver_signing.ps1,
# which needs an EV certificate and an attestation submission — neither of which
# belongs in a Makefile target anyone can run.
sign:
	@echo "Test-signing for local development."
	@echo "The target machine must be in test-signing mode:"
	@echo "  bcdedit /set testsigning on   (then reboot)"
	signtool sign /v /s PrivateCertStore /n UnifiedFirewallTest /fd sha256 \
		$(PLATFORM)/$(CONFIGURATION)/ufw.sys

generated:
	@if [ ! -f "$(GENERATED)/ufw_policy_generated.h" ]; then \
		echo "note: $(GENERATED)/ufw_policy_generated.h not found."; \
		echo "      The driver does not need it — policy normally arrives"; \
		echo "      over IOCTL from ufwd. Run 'make generate' in the"; \
		echo "      repository root to bake a policy in instead."; \
	fi

clean:
	$(MSBUILD) $(PROJECT) /p:Configuration=$(CONFIGURATION) /p:Platform=$(PLATFORM) /t:Clean
