//! The ring-0 fault latch decides when to pull the module out of the packet
//! path. That decision is the kind of thing you can normally only observe by
//! actually crash-looping a kernel — so, like the DPI headers, the logic lives
//! in a kernel-free header (`kernel/linux/inc/boot_watchdog.h`) that a hosted
//! compiler can build and run.
//!
//! This test compiles that exact header into a small C harness, runs the
//! escalation ladder — no trip below the threshold, a trip at it, stickiness,
//! reset, window pruning, forced trip, threshold clamping, a backwards clock —
//! and asserts the harness exits clean. If a check fails the harness names it
//! and exits non-zero, so a regression points at the broken property rather
//! than a mismatched output string.
//!
//! Without a C compiler the test says so and passes, rather than failing a Rust
//! developer's machine for lacking a toolchain they do not otherwise need.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

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

const HARNESS: &str = r#"
#include <stdio.h>
#include "boot_watchdog.h"

#define S 1000000000ULL /* one second in nanoseconds */

static int fails = 0;
#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            printf("FAIL: %s\n", msg);                                         \
            fails++;                                                           \
        }                                                                      \
    } while (0)

int main(void)
{
    struct ufw_fault_latch l;

    /* Below the threshold: no trip. At it: trip. */
    ufw_latch_init(&l, 3, 60 * S);
    CHECK(!ufw_latch_is_tripped(&l), "fresh latch is not tripped");
    CHECK(ufw_latch_on_fault(&l, 1 * S) == 0, "fault 1 does not trip");
    CHECK(ufw_latch_on_fault(&l, 2 * S) == 0, "fault 2 does not trip");
    CHECK(ufw_latch_on_fault(&l, 3 * S) == 1, "fault 3 trips");
    CHECK(ufw_latch_is_tripped(&l), "latched after the threshold");
    CHECK(l.trips == 1, "exactly one trip recorded");

    /* Sticky: further faults stay tripped, do not double-count the trip, but
     * do keep counting total faults. */
    CHECK(ufw_latch_on_fault(&l, 4 * S) == 1, "stays tripped");
    CHECK(l.trips == 1, "trip not double-counted");
    CHECK(l.total_faults == 4, "total faults counts post-latch faults");

    /* Reset re-arms. */
    ufw_latch_reset(&l);
    CHECK(!ufw_latch_is_tripped(&l), "reset clears the latch");
    CHECK(l.count == 0, "reset empties the ring");

    /* Faults spread wider than the window never accumulate into a trip. */
    ufw_latch_init(&l, 3, 10 * S);
    {
        int i;
        for (i = 0; i < 40; i++)
            CHECK(ufw_latch_on_fault(&l, (__u64)i * 100 * S) == 0,
                  "a fault every 100s never trips a 10s window");
    }
    CHECK(!ufw_latch_is_tripped(&l), "spread faults leave the latch clear");

    /* The forced trip: the boot-recovery path. */
    ufw_latch_init(&l, 3, 60 * S);
    ufw_latch_force(&l);
    CHECK(ufw_latch_is_tripped(&l), "force trips immediately");
    CHECK(l.trips == 1, "force records one trip");

    /* Threshold clamping keeps the ladder coherent. */
    ufw_latch_init(&l, 0, 60 * S);
    CHECK(l.max_faults == 1, "max_faults floors at 1");
    CHECK(ufw_latch_on_fault(&l, 1 * S) == 1, "a single fault trips at max=1");
    ufw_latch_init(&l, 100, 60 * S);
    CHECK(l.max_faults == UFW_LATCH_RING, "max_faults caps at the ring size");

    /* A clock that appears to move backwards must not spuriously trip. */
    ufw_latch_init(&l, 2, 60 * S);
    CHECK(ufw_latch_on_fault(&l, 100 * S) == 0, "backwards: first fault");
    CHECK(ufw_latch_on_fault(&l, 10 * S) == 0,
          "backwards: an earlier timestamp does not manufacture a second in-window fault");
    CHECK(!ufw_latch_is_tripped(&l), "backwards clock leaves the latch clear");

    if (fails) {
        printf("%d boot-watchdog check(s) failed\n", fails);
        return 1;
    }
    printf("all boot-watchdog checks passed\n");
    return 0;
}
"#;

#[test]
fn the_ring0_fault_latch_behaves() {
    let Some(cc) = c_compiler() else {
        eprintln!("no C compiler found; skipping the boot-watchdog hosted test");
        return;
    };

    let dir = std::env::temp_dir().join(format!(
        "ufw-bootwd-{}-{}",
        std::process::id(),
        ufw_shared::now_us()
    ));
    std::fs::create_dir_all(&dir).expect("scratch directory");
    let src = dir.join("harness.c");
    let bin = dir.join("harness");
    std::fs::write(&src, HARNESS).expect("write harness");

    let include = repo_root().join("kernel/linux/inc");
    let compile = Command::new(cc)
        .arg("-std=c11")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-O2")
        .arg("-I")
        .arg(&include)
        .arg("-o")
        .arg(&bin)
        .arg(&src)
        .output()
        .expect("run the compiler");
    assert!(
        compile.status.success(),
        "the boot-watchdog header must compile cleanly:\n{}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let run = Command::new(&bin).output().expect("run the harness");
    assert!(
        run.status.success(),
        "boot-watchdog checks failed:\n{}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );

    let _ = std::fs::remove_dir_all(&dir);
}
