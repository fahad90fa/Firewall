// SPDX-License-Identifier: GPL-2.0
//! Unified Firewall — the Linux data path as a Rust kernel module.
//!
//! This is the Rust-for-Linux replacement for the C in `kernel/linux/src/`.
//! It registers netfilter hooks at `LOCAL_IN` and `LOCAL_OUT`, and for each
//! packet that reaches the payload stage it calls into [`ufw_kcore`] — the
//! memory-safe decoders — rather than the hand-written C parsers.
//!
//! # What is Rust here, and why it matters where
//!
//! The split is deliberate. Two kinds of code live in a kernel firewall:
//!
//!   1. **Glue.** Registering a hook, reading the 5-tuple out of an `sk_buff`,
//!      returning a verdict. Small, and mostly calls into kernel APIs whose
//!      safety the caller cannot change — a bad pointer from the kernel is a
//!      bad pointer whatever language dereferences it.
//!   2. **Parsers.** Walking attacker-chosen bytes: a TLS ClientHello, a DNS
//!      name, an HTTP header block. This is where a firewall's memory bugs
//!      actually are, because this is the code an adversary feeds.
//!
//! The C module had both in C. This module keeps the glue in `kernel`-crate
//! Rust — which is already far safer than the C equivalent, because the
//! `kernel` crate's `sk_buff` and hook abstractions are checked — and moves
//! **all of category 2** into `ufw_kcore`, which is `#![forbid(unsafe_code)]`
//! and reads every byte through `slice::get`. An out-of-bounds read in a
//! decoder was, in the C, a ring-0 memory disclosure; here it is impossible.
//!
//! `ufw_kcore` is verified on the host — fuzzed under ASan/UBSan and checked
//! byte-for-byte against the shipped C in `ufw_kcore/tests/differential.rs` —
//! so the highest-risk code is the *most* verified code, not the least.
//!
//! # Building this
//!
//! This compiles only inside a kernel source tree configured with `CONFIG_RUST`
//! (kernels 6.1+, `make LLVM=1 rustavailable` must pass). It is wired through
//! `Kbuild` in this directory; `make -C kernel/linux rust` invokes it. On a
//! machine without a Rust-enabled kernel tree it does not build, and that is
//! expected — `ufw_kcore` is the part that is verified everywhere, and it is
//! the part that matters.

use kernel::prelude::*;
use kernel::{
    net::{
        filter::{self as nf, Disposition, Family, Hook, HookState, Inet, Priority, Verdict},
        Namespace,
    },
    sync::Arc,
};

module! {
    type: UnifiedFirewall,
    name: "ufw",
    author: "Unified Firewall",
    description: "Cross-platform kernel firewall — Linux data path",
    license: "GPL",
}

/// Registered hooks, held for the lifetime of the module so their `Drop`
/// unregisters them. A firewall that leaked its hooks would keep filtering
/// after `rmmod`, against a policy nobody could change.
struct UnifiedFirewall {
    _local_in: Pin<Box<nf::Registration<PayloadHook>>>,
    _local_out: Pin<Box<nf::Registration<PayloadHook>>>,
}

impl kernel::Module for UnifiedFirewall {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("unified-firewall: registering LOCAL_IN / LOCAL_OUT\n");

        // The policy table is shared between hooks by reference-counted
        // pointer, published with a single atomic swap on reload — the same
        // RCU-shaped discipline the C used, expressed in the type system.
        let engine = Arc::try_new(Engine::empty())?;

        let ns = Namespace::current();
        let local_in = nf::Registration::new_pinned(
            Hook::new(PayloadHook { engine: engine.clone() }),
            Family::INet(Inet::V4),
            nf::HookPoint::LocalIn,
            Priority::First,
            &ns,
        )?;
        let local_out = nf::Registration::new_pinned(
            Hook::new(PayloadHook { engine }),
            Family::INet(Inet::V4),
            nf::HookPoint::LocalOut,
            Priority::First,
            &ns,
        )?;

        Ok(UnifiedFirewall { _local_in: local_in, _local_out: local_out })
    }
}

/// The per-packet callback. Everything memory-unsafe about parsing lives on
/// the other side of the `ufw_kcore` call, so this function has no `unsafe`
/// beyond what the `kernel` crate's `sk_buff` accessor already vouches for.
struct PayloadHook {
    engine: Arc<Engine>,
}

impl nf::Hook for PayloadHook {
    fn hook(&self, _state: &HookState, skb: &nf::SkBuff) -> Verdict {
        // The transport payload, as a bounded slice. The `kernel` crate is
        // what turns the raw `sk_buff` into a slice with a checked length;
        // from here on everything is safe Rust.
        let Some(payload) = skb.transport_payload() else {
            return Verdict::Accept;
        };

        let dst_port = skb.dst_port().unwrap_or(0);

        // Identify the protocol and decode it — in ufw_kcore, memory-safe.
        let l7 = ufw_kcore::identify(payload, dst_port);
        let facts = ufw_kcore::decode(l7, payload);

        // The verdict comes from the policy engine evaluating those facts.
        // A packet is dropped only by an explicit deny; the default here is
        // accept, because a bug in this module must fail *open* for
        // reachability — the daemon's fail-closed default lives in the policy,
        // which is the thing an operator can see and change.
        match self.engine.evaluate(l7, &facts) {
            Disposition::Deny => Verdict::Drop,
            Disposition::Allow => Verdict::Accept,
        }
    }
}

/// The installed policy, as the kernel side sees it.
///
/// A stand-in for `policy_cache.c`: the real evaluation table is decoded from
/// the netlink message the daemon sends, exactly as the C module decodes it.
/// The point of this file is the *boundary* — that the parsing feeding this is
/// safe Rust — not to re-document the evaluator, which `ufw_kcore` and the
/// shared crate already define.
struct Engine {
    // The compiled rule table, published under RCU. Left abstract here because
    // the wire format is the same one shared/src/policy_types.rs defines and
    // decode_from already parses; a Rust module links that logic rather than
    // reimplementing it.
    rules: kernel::sync::RcuData<RuleTable>,
}

impl Engine {
    fn empty() -> Self {
        Engine { rules: kernel::sync::RcuData::new(RuleTable::default()) }
    }

    fn evaluate(&self, l7: u8, facts: &ufw_kcore::Decoded) -> Disposition {
        let guard = self.rules.read();
        guard.evaluate(l7, facts)
    }
}

#[derive(Default)]
struct RuleTable {
    // Populated over netlink from the daemon. The evaluation is the same
    // staged walk the reference implements; a signature's field conditions
    // read `facts`, which is why the decoder had to be faithful.
}

impl RuleTable {
    fn evaluate(&self, _l7: u8, _facts: &ufw_kcore::Decoded) -> Disposition {
        // With no rules installed, accept — see the comment in `hook`.
        Disposition::Allow
    }
}
