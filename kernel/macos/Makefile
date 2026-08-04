# Unified Firewall — macOS Network Extension.
#
# Wraps xcodebuild. Must run on macOS with Xcode installed; there is no
# cross-compilation path for a System Extension, because signing and
# entitlement validation happen at build time against the local keychain.
#
# Targets:
#   make              build the app, the system extension and the filter
#   make release      signed release build (needs a Developer ID identity)
#   make install      copy to /Applications and request activation
#   make activate     request activation of an already-installed bundle
#   make status       what the system thinks is installed and why
#   make uninstall
#   make clean
#
# Why `make install` does not just work:
#
# macOS will not activate a system extension from an arbitrary directory. The
# containing app has to be in /Applications, signed, and — on an unmanaged Mac
# — approved by a human in System Settings. `make status` exists because the
# failure modes are hard to tell apart from the outside: not installed, waiting
# for approval, approved but disabled, and activated-but-crashing all present as
# "the firewall is not working".

XCODEBUILD ?= xcodebuild
PROJECT := UnifiedFirewall.xcodeproj
SCHEME ?= UnifiedFirewall
CONFIGURATION ?= Debug
DERIVED ?= build

# Where `make generate` in the repository root puts the compiled policy.
GENERATED ?= ../../build/generated/macos

APP := /Applications/UnifiedFirewall.app
EXTENSION_ID := com.unifiedfirewall.extension

.PHONY: all release install activate status uninstall clean generated

all: generated
	$(XCODEBUILD) -project $(PROJECT) -scheme $(SCHEME) \
		-configuration $(CONFIGURATION) -derivedDataPath $(DERIVED) build

release: generated
	$(XCODEBUILD) -project $(PROJECT) -scheme $(SCHEME) \
		-configuration Release -derivedDataPath $(DERIVED) \
		CODE_SIGN_STYLE=Manual build

generated:
	@if [ ! -f "$(GENERATED)/UFWPolicy.generated.swift" ]; then \
		echo "error: $(GENERATED)/UFWPolicy.generated.swift is required."; \
		echo "       Unlike the two kernel modules, the extension compiles the"; \
		echo "       policy in: it starts enforcing before the daemon connects,"; \
		echo "       so it needs a rule table at build time. Run 'make generate'"; \
		echo "       in the repository root."; \
		exit 1; \
	fi

install: all
	rm -rf $(APP)
	cp -R $(DERIVED)/Build/Products/$(CONFIGURATION)/UnifiedFirewall.app /Applications/
	@echo
	@echo "Installed. Now run:  make activate"
	@echo "Then approve the extension in System Settings > Privacy & Security."

activate:
	@if [ ! -d "$(APP)" ]; then \
		echo "error: $(APP) not found. Run 'make install' first."; \
		echo "       macOS will not activate a system extension from anywhere"; \
		echo "       other than /Applications."; \
		exit 1; \
	fi
	open $(APP) --args --activate

status:
	@echo "=== system extensions ==="
	@systemextensionctl list || true
	@echo
	@echo "=== content filter configuration ==="
	@scutil --nc list 2>/dev/null | grep -i filter || echo "(no filter configuration)"
	@echo
	@echo "=== extension process ==="
	@pgrep -fl "$(EXTENSION_ID)" || echo "(not running)"
	@echo
	@echo "If the extension is listed as [activated waiting for user],"
	@echo "approve it in System Settings > Privacy & Security."

uninstall:
	systemextensionctl uninstall - $(EXTENSION_ID) || true
	rm -rf $(APP)

clean:
	$(XCODEBUILD) -project $(PROJECT) -scheme $(SCHEME) \
		-configuration $(CONFIGURATION) -derivedDataPath $(DERIVED) clean
	rm -rf $(DERIVED)
