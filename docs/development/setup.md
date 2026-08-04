# Development setup

## The short version

```sh
git clone https://github.com/fahad90fa/Firewall && cd Firewall
cargo test --workspace
```

That is the whole setup for everything except the kernel modules. The workspace
has **no external dependencies**, so there is nothing to fetch and nothing to
vendor.

## What you need for what

| Working on | You need |
| --- | --- |
| Compiler, daemon, CLI, tests | Rust 1.74+ |
| The ABI drift tests | …plus any C compiler (`cc`, `gcc`, `clang`) |
| Linux kernel module | …plus kernel headers, clang with a bpf target, `libbpf-dev`, `bpftool` |
| Windows driver | Visual Studio + the matching WDK |
| macOS extension | Xcode, an Apple Developer account for signing |

The ABI tests skip themselves with a message when no C compiler is present,
rather than failing a Rust developer's machine for lacking a toolchain they do
not otherwise need.

## First things to run

```sh
cargo test --workspace         # 722 tests, a few seconds
make policies                  # every shipped example still compiles
```

Then the thing that shows what the project actually does:

```sh
cargo build --release
./target/release/ufwctl policy explain \
    policies/test/regression_basic.yaml tcp:10.0.0.5:443:out
```

The per-platform table at the bottom is the whole thesis.

## Kernel work

### Linux

```sh
sudo apt install build-essential clang llvm libbpf-dev bpftool linux-headers-$(uname -r)

make generate                  # the eBPF program needs a rule table to compile
make -C kernel/linux           # module + eBPF objects
sudo make -C kernel/linux check    # runs the REAL eBPF verifier
```

`check` is the one worth running before you push. An eBPF program that compiles
but exceeds the instruction budget is a program that will be rejected at load
time on a production host, and finding that out here costs seconds.

If you would rather not install a toolchain:

```sh
make docker-test               # compiles everything and runs the verifier
```

### Windows

```
make -C kernel\windows              # debug
make -C kernel\windows analyze      # Code Analysis
make -C kernel\windows sdv          # Static Driver Verifier — slow
```

For loading a driver locally: `bcdedit /set testsigning on`, reboot, then
`build\windows\driver_signing.ps1 -TestSign`.

### macOS

```sh
brew install xcodegen
make generate                  # REQUIRED: the extension compiles its policy in
make -C kernel/macos
```

The Xcode project is generated from `project.yml` rather than committed —
`project.pbxproj` has unstable object identifiers, so two people adding a file
produce a conflict git cannot merge and a human cannot read.

## Layout, and where to start reading

```
policy-lang/    the compiler — start with src/lib.rs, then compiler/mod.rs
daemon/         ufwd — start with src/main.rs, which documents the startup order
cli/            ufwctl
shared/         the contracts: policy_types.rs is the one that matters
kernel/         three enforcement points; each classify.c/.swift opens with why
tests/          end-to-end scenarios + the containerised Linux environment
```

Every source file opens with a header explaining why it exists and what would
break if it were written differently. Those headers are the documentation; this
tree is the map.

## Two things worth knowing before you change anything

**Stages are not priorities.** Rules evaluate in stage order — perimeter, packet,
identity, app-DPI, stream — and `priority:` orders rules *within* a stage. A
catch-all at the packet layer pre-empts every identity rule beneath it whatever
the numbers say. Two of this repository's own example policies got this wrong.

**The decision procedure exists four times**: `shared/src/policy_types.rs`
(reference), `kernel/linux/src/classify.c`, `kernel/windows/src/classify.c`,
`kernel/macos/NetworkExtension/RuleEngine.swift`. A change to one is a change to
all four in the same commit. The equivalence verifier will tell you if you missed
one — that is what it is for.

## Editor

`rust-analyzer` works with no configuration. For the C, point your tooling at
`kernel/linux/inc` or `kernel/windows/inc`; both headers are self-contained
enough to parse without a kernel tree (`policy_structs.h` under `#ifndef
__KERNEL__`, `ipc_ioctl.h` under `UFW_ABI_CHECK`), which is also how the ABI
tests run anywhere.
