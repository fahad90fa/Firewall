//! The generated C headers must compile against the kernel's own structures.
//!
//! The compiler's Linux backend emits `ufw_rules.h` as a designated-initialiser
//! list over `struct ufw_rule`, which is declared by hand in
//! `kernel/linux/inc/policy_structs.h`. Nothing else checks that the two agree:
//! the Rust side compiles fine with a field the C struct does not have, and the
//! C side compiles fine until someone actually builds the module — on a machine
//! with kernel headers, which CI for a Rust workspace does not have.
//!
//! So this test does the one thing that catches it: run a C compiler over the
//! generated header and the kernel header together. It needs only a hosted C
//! compiler, not a kernel tree, because `policy_structs.h` is deliberately
//! self-contained under `#ifndef __KERNEL__`.
//!
//! If no C compiler is available the test reports that and passes, rather than
//! failing a Rust developer's machine for lacking a toolchain they do not
//! otherwise need.

use std::path::{Path, PathBuf};
use std::process::Command;

use ufw_policy_lang::{compile_str, CompileOptions};
use ufw_shared::Platform;

const POLICY: &str = "\
version: 1
metadata:
  name: abi-check
defaults:
  action: deny
address_groups:
  internal: [10.0.0.0/8]
port_groups:
  web: [80, 443]
applications:
  agent:
    trust: [\">= known\"]
    platforms:
      linux:
        paths: [/usr/bin/agent]
      windows:
        path: \"C:\\\\agent.exe\"
        signer: \"Contoso Ltd\"
      macos:
        team_id: ABCDE12345
signature_groups:
  bad: [http-exploit-post]
rules:
  - id: allow-icmp
    priority: 10
    layer: packet
    action: allow
    protocol: icmp
  - id: allow-internal-web
    priority: 100
    layer: packet
    direction: outbound
    action: allow
    protocol: tcp
    destination:
      addresses: [internal]
      ports: web
  - id: agent-egress
    priority: 200
    direction: outbound
    action: allow
    protocol: tcp
    application: agent
    destination:
      ports: web
    schedule:
      days: [weekdays]
      start: \"08:00\"
      end: \"18:00\"
  - id: block-exploits
    priority: 300
    layer: stream
    action: allow
    protocol: tcp
    dpi:
      signatures: [bad]
      protocols: [http]
      on_match: deny
";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

/// The first C compiler on this machine, if any.
fn c_compiler() -> Option<&'static str> {
    for candidate in ["cc", "gcc", "clang"] {
        let ok = Command::new(candidate)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            return Some(candidate);
        }
    }
    None
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ufw-abi-{}-{}-{name}",
        std::process::id(),
        ufw_shared::now_us()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn the_generated_linux_header_compiles_against_the_kernel_structs() {
    let Some(cc) = c_compiler() else {
        eprintln!("no C compiler found; skipping the kernel ABI check");
        return;
    };

    let inc = repo_root().join("kernel/linux/inc");
    if !inc.join("policy_structs.h").exists() {
        eprintln!("kernel/linux/inc not present; skipping");
        return;
    }

    let result = compile_str("abi-check", POLICY, &CompileOptions::default());
    assert!(result.is_ok(), "{}", result.render());

    let artifact = result.artifact(Platform::Linux).expect("linux artifact");
    let dir = scratch("linux");

    for file in &artifact.files {
        // Artifact paths are prefixed with the platform directory.
        let name = Path::new(&file.path)
            .file_name()
            .expect("artifact file name");
        std::fs::write(dir.join(name), &file.contents).unwrap();
    }

    let main = dir.join("abi_check.c");
    std::fs::write(
        &main,
        r#"
#include <stdint.h>
#include <string.h>
#include "policy_structs.h"
#include "ufw_rules.h"

/* The generated table must be exactly as long as the count it declares, and
 * every rule's stage must be a real stage. A mismatch here means the emitter
 * and this header disagree about the shape of a rule. */
_Static_assert(sizeof(ufw_rules) / sizeof(ufw_rules[0]) == UFW_RULE_COUNT,
               "generated rule count disagrees with the generated table");
_Static_assert(UFW_ABI_REVISION_EXPECTED == UFW_ABI_REVISION,
               "the compiler generated for a different ABI revision than this "
               "header declares");

int main(void)
{
        unsigned i;

        for (i = 0; i < UFW_RULE_COUNT; i++) {
                if (ufw_rules[i].stage >= UFW_STAGE__COUNT)
                        return 1;
                if (ufw_rules[i].name[0] == '\0')
                        return 2;
        }
        return 0;
}
"#,
    )
    .unwrap();

    let output = Command::new(cc)
        .arg("-std=c11")
        .arg("-Wall")
        .arg("-Werror")
        .arg("-I")
        .arg(&inc)
        .arg("-I")
        .arg(&dir)
        .arg("-o")
        .arg(dir.join("abi_check"))
        .arg(&main)
        .output()
        .expect("running the C compiler");

    assert!(
        output.status.success(),
        "the generated Linux header does not compile against \
         kernel/linux/inc/policy_structs.h:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // And it must actually run: the loop above checks that every generated
    // stage is one this header knows about, which a compile alone cannot.
    let run = Command::new(dir.join("abi_check"))
        .output()
        .expect("running the ABI check");
    assert!(
        run.status.success(),
        "the generated table failed its runtime checks (exit {:?})",
        run.status.code()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_generated_ebpf_header_compiles_against_the_fast_path_structs() {
    let Some(cc) = c_compiler() else {
        eprintln!("no C compiler found; skipping the eBPF ABI check");
        return;
    };

    let ebpf = repo_root().join("kernel/linux/ebpf");
    if !ebpf.join("common.h").exists() {
        eprintln!("kernel/linux/ebpf not present; skipping");
        return;
    }

    let result = compile_str("abi-check", POLICY, &CompileOptions::default());
    let artifact = result.artifact(Platform::Linux).expect("linux artifact");
    let dir = scratch("ebpf");

    for file in &artifact.files {
        let name = Path::new(&file.path).file_name().unwrap();
        std::fs::write(dir.join(name), &file.contents).unwrap();
    }

    // Without this the C loop below is vacuous, and a compiler regression that
    // emitted an empty fast-path table would pass this test silently.
    let rules_header = std::fs::read_to_string(dir.join("ufw_ebpf_rules.h")).unwrap();
    assert!(
        !rules_header.contains("#define UFW_EBPF_RULE_COUNT 0"),
        "the fast-path table is empty, so the checks below prove nothing:\n{rules_header}"
    );

    let main = dir.join("ebpf_abi_check.c");
    std::fs::write(
        &main,
        r#"
#include <stdint.h>
/* common.h is written for the bpf target, but everything the generated header
 * depends on is plain C: the struct layout and the verdict constants. Pulling
 * in only that is what lets this check run without a bpf toolchain. */
#include "common.h"
#include "ufw_ebpf_rules.h"

_Static_assert(UFW_EBPF_RULE_COUNT <= UFW_EBPF_MAX_RULES,
               "the compiler emitted more fast-path rules than the verifier "
               "budget allows");

int main(void)
{
        unsigned i;

        for (i = 0; i < UFW_EBPF_RULE_COUNT; i++) {
                if (ufw_ebpf_rules[i].src_n > UFW_EBPF_MAX_CIDRS)
                        return 1;
                if (ufw_ebpf_rules[i].dst_n > UFW_EBPF_MAX_CIDRS)
                        return 2;
                if (ufw_ebpf_rules[i].src_port_n > UFW_EBPF_MAX_PORTS)
                        return 3;
                if (ufw_ebpf_rules[i].dst_port_n > UFW_EBPF_MAX_PORTS)
                        return 4;
                /* The fast path is ingress-only, so an outbound-scoped rule
                 * in the prefix would never be evaluated — and the compiler
                 * should not have put one there. */
                if (ufw_ebpf_rules[i].direction == UFW_DIR_OUTBOUND)
                        return 5;
        }
        return 0;
}
"#,
    )
    .unwrap();

    let output = Command::new(cc)
        .arg("-std=c11")
        .arg("-Wall")
        .arg("-Werror")
        .arg("-I")
        .arg(&ebpf)
        .arg("-I")
        .arg(&dir)
        .arg("-o")
        .arg(dir.join("ebpf_abi_check"))
        .arg(&main)
        .output()
        .expect("running the C compiler");

    assert!(
        output.status.success(),
        "the generated eBPF header does not compile against \
         kernel/linux/ebpf/common.h:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let run = Command::new(dir.join("ebpf_abi_check"))
        .output()
        .expect("running the eBPF ABI check");
    assert!(
        run.status.success(),
        "the generated fast-path table failed its bounds checks (exit {:?}); \
         see kernel/linux/ebpf/common.h for what each code means",
        run.status.code()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_generated_windows_header_compiles_against_the_driver_abi() {
    // `kernel/windows/inc/ipc_ioctl.h` has a UFW_ABI_CHECK mode that supplies
    // the handful of scalar types the declarations use, so this runs without a
    // Windows SDK. Without it nothing checks that the Rust emitter and the
    // driver's structures agree until someone builds the driver on a machine
    // with the WDK — which is exactly when it is most expensive to find out.
    let Some(cc) = c_compiler() else {
        eprintln!("no C compiler found; skipping the Windows ABI check");
        return;
    };

    let inc = repo_root().join("kernel/windows/inc");
    if !inc.join("ipc_ioctl.h").exists() {
        eprintln!("kernel/windows/inc not present; skipping");
        return;
    }

    let result = compile_str("abi-check", POLICY, &CompileOptions::default());
    assert!(result.is_ok(), "{}", result.render());

    let artifact = result
        .artifact(Platform::Windows)
        .expect("windows artifact");
    let dir = scratch("windows");
    for file in &artifact.files {
        let name = Path::new(&file.path).file_name().unwrap();
        std::fs::write(dir.join(name), &file.contents).unwrap();
    }

    let main = dir.join("win_abi_check.c");
    std::fs::write(
        &main,
        r#"
#include <stdint.h>
#include "ipc_ioctl.h"
#include "ufw_policy_generated.h"

_Static_assert(sizeof(g_ufwGeneratedFilters) / sizeof(g_ufwGeneratedFilters[0]) ==
                       UFW_GENERATED_FILTER_COUNT,
               "generated filter count disagrees with the generated table");
_Static_assert(UFW_GENERATED_ABI_REVISION == UFW_ABI_REVISION,
               "the compiler generated for a different ABI revision than the "
               "driver header declares");

int main(void)
{
        unsigned i;

        for (i = 0; i < UFW_GENERATED_FILTER_COUNT; i++) {
                const UFW_FILTER_SPEC *f = &g_ufwGeneratedFilters[i];

                if (f->stage >= UFW_STAGE_COUNT)
                        return 1;
                if (f->name == 0 || f->name[0] == '\0')
                        return 2;
                /* WFP sorts descending, the reference ascending; the emitted
                 * weight is UINT64_MAX minus the evaluation key, so a weight
                 * of zero means the key overflowed. */
                if (f->weight == 0)
                        return 3;
                /* A filter at a flow stage must be scoped to the protocols ALE
                 * can see, or it would be installed at a layer that never
                 * fires for it. */
                if (f->stage >= UFW_STAGE_IDENTITY &&
                    f->protocolScope == UFW_SCOPE_CONNECTIONLESS)
                        return 4;
        }
        return 0;
}
"#,
    )
    .unwrap();

    let output = Command::new(cc)
        .arg("-std=c11")
        .arg("-Wall")
        .arg("-Werror")
        .arg("-DUFW_ABI_CHECK")
        .arg("-I")
        .arg(&inc)
        .arg("-I")
        .arg(&dir)
        .arg("-o")
        .arg(dir.join("win_abi_check"))
        .arg(&main)
        .output()
        .expect("running the C compiler");

    assert!(
        output.status.success(),
        "the generated Windows header does not compile against \
         kernel/windows/inc/ipc_ioctl.h:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let run = Command::new(dir.join("win_abi_check"))
        .output()
        .expect("running the Windows ABI check");
    assert!(
        run.status.success(),
        "the generated filter table failed its checks (exit {:?}); \
         see the C source in this test for what each code means",
        run.status.code()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_generated_ebpf_table_carries_no_ipv6_prefix() {
    // `struct ufw_ebpf_cidr` is IPv4-only, and for a while the emitter wrote
    // `.family`/`.v6` initialisers into it. The consequence was not a wrong
    // verdict — it was the eBPF programs failing to compile, which nothing in
    // this suite noticed because the ABI policy above happens to put no
    // address-bearing rule in the eligible prefix.
    //
    // So this uses a policy that does, and checks the shape of what comes out.
    let source = "\
version: 1
defaults:
  action: deny
rules:
  - id: drop-multicast
    priority: 10
    layer: packet
    direction: inbound
    action: deny
    protocol: tcp
    source:
      addresses: [224.0.0.0/4, fe80::/10]
";
    let result = compile_str("ebpf-cidr", source, &CompileOptions::default());
    assert!(result.is_ok(), "{}", result.render());

    let artifact = result.artifact(Platform::Linux).expect("linux artifact");
    let header = &artifact
        .files
        .iter()
        .find(|f| f.path.ends_with("ufw_ebpf_rules.h"))
        .expect("generated eBPF header")
        .contents;

    assert!(
        !header.contains(".family") && !header.contains(".v6"),
        "the eBPF table uses fields `struct ufw_ebpf_cidr` does not have:\n{header}"
    );
    // And the rule must not have been silently narrowed: a rule the fast path
    // cannot express in full belongs on the slow path entirely, not on the
    // fast path with half its addresses.
    assert!(
        header.contains("#define UFW_EBPF_RULE_COUNT 0"),
        "a rule with an IPv6 prefix should not be eBPF-eligible at all:\n{header}"
    );
}
