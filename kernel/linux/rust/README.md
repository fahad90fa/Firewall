# The Linux data path in Rust

This is item 3 of the hardening plan — *get the C out of ring 0* — done the
way it is actually worth doing.

## The idea

A kernel firewall has two kinds of code:

- **Parsers** that walk attacker-chosen bytes (a TLS ClientHello, a DNS name,
  an HTTP header block). This is where the memory bugs are, because this is the
  code an adversary feeds.
- **Glue** that registers a hook and reads a 5-tuple. Small, and it mostly
  calls kernel APIs whose safety no language choice changes.

Rewriting *everything* in Rust is a multi-month effort whose kernel-glue half
cannot even be compiled without a Rust-enabled kernel tree. But the half that
matters — the parsers — can be moved out of hand-written C into memory-safe
Rust **that builds and is verified on any machine**.

## What is here

| | |
| --- | --- |
| `ufw_kcore/` | The parsers, as `#![no_std] #![forbid(unsafe_code)]` Rust. A faithful port of `kernel/linux/inc/dpi_decoders.h`. Builds and tests everywhere. |
| `module.rs` | The Rust-for-Linux netfilter module: hook registration and verdict, calling into `ufw_kcore`. Builds only in a `CONFIG_RUST` kernel tree. |
| `Kbuild` | Wires `module.rs` into a kernel build. |

## Why the split is the point

In the C decoders, an out-of-bounds read was a ring-0 memory disclosure that
the hand-written bounds checks had to prevent by inspection. In `ufw_kcore` it
is a `None` from `slice::get`, enforced by the compiler — there is no `unsafe`,
and every byte read and every wrapping arithmetic is spelled out so nothing
panics on a crafted length either.

And it is *verified*:

- `cargo test -p ufw-kcore` runs it, including truncation of every seed prefix.
- `ufw_kcore/tests/differential.rs` compiles the shipped C header and checks
  the Rust and the C agree on every extracted field across ~8,000 mutated
  payloads. A port is only worth having if it is faithful — the equivalence
  claim reaches down to the facts the decoders extract — and this is the proof
  that it is.

So the highest-risk code became the *most*-verified code, on every machine,
today. That is the whole of what "get the C out of ring 0" buys, delivered
without waiting for a kernel that can build the glue.

## Building the module

```sh
# Everywhere: verify the memory-safe core.
make -C kernel/linux rust-check

# In a CONFIG_RUST kernel tree (6.1+, `make rustavailable` passes):
make -C kernel/linux rust KDIR=/path/to/linux
insmod rust/ufw.ko
```

The Rust module and the C module are **alternatives**, not a stack: a host runs
one, and the daemon reports which. Until a deployment has a Rust-enabled
kernel, the C module ships and `ufw_kcore` is the answer to "is the risky
parsing memory-safe" — because the C decoders and this Rust are proven to
behave identically, a bug found in one is a bug in both, and the Rust cannot
have the memory-safety class of bug at all.
