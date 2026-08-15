/*
 * libFuzzer entry point for the Aho-Corasick table decoder and scan.
 *
 * The daemon builds the multi-pattern automaton and ships the finished table to
 * the kernel over netlink (see daemon/src/automaton.rs). The kernel half —
 * kernel/linux/inc/dpi_automaton.h — decodes that table and walks it over the
 * reassembled stream. Both halves run in ring 0 on bytes the kernel did not
 * build itself: the daemon is trusted to be the daemon, but "trusted to be the
 * peer" is not "trusted to be correct", and the header's own comment says the
 * decode bounds-checks every index precisely so the traversal needs none.
 *
 * That decoder is a parser, and a parser of a length-prefixed binary format
 * with per-state transition and output slices is exactly where an off-by-one
 * becomes an out-of-bounds index. The in-tree differential test
 * (policy-lang/tests/dpi_automaton_tests.rs) checks the *result* against a Rust
 * reference on a fixed corpus; this is the coverage-guided, sanitized other
 * half, the same split decoders.c is to dpi_decoder_tests.rs.
 *
 * The four table arrays are allocated here at exactly the size ufw_ac_sizes_of
 * reports — no slack — so AddressSanitizer flags any index ufw_ac_load or
 * ufw_ac_scan forms past the end of its slice, which a kernel pool allocation
 * with headroom could hide.
 *
 *   clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *         -fno-sanitize-recover=all \
 *         -I ../kernel/linux/inc -o fuzz-automaton automaton.c
 *   ./fuzz-automaton corpus-automaton/ -max_len=65536 -jobs=$(nproc)
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "dpi_automaton.h"

/* The kernel never scans past the reassembly budget, so neither does the
 * harness — fuzzing a longer buffer would explore a path production never has. */
#define UFW_STREAM_FUZZ_CAP (32u * 1024u)

/* Allocate n elements of `sz`, never zero bytes (a zero-length slice is legal —
 * a trie can carry no transitions — and malloc(0) is allowed to return NULL,
 * which would be indistinguishable from failure). The extra element is never
 * addressed, so ASan still catches a real over-index into the used range. */
static void *xalloc(size_t n, size_t sz)
{
	return calloc(n ? n : 1, sz);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct ufw_ac_cursor cur = { (const __u8 *)data, size, 0 };
	struct ufw_ac_sizes sizes;
	struct ufw_ac ac;
	struct ufw_ac_hit *hits = NULL;
	__u32 scan_len;
	__u8 t;

	/* Sizing pass. A malformed or oversized table is rejected here, which is
	 * the decoder doing its job, not a finding. */
	if (!ufw_ac_sizes_of(&cur, &sizes))
		return 0;

	memset(&ac, 0, sizeof(ac));
	ac.patterns    = xalloc(sizes.patterns, sizeof(*ac.patterns));
	ac.states      = xalloc(sizes.states, sizeof(*ac.states));
	ac.transitions = xalloc(sizes.transitions, sizeof(*ac.transitions));
	ac.outputs     = xalloc(sizes.outputs, sizeof(*ac.outputs));
	if (!ac.patterns || !ac.states || !ac.transitions || !ac.outputs)
		goto out;

	/* Fill pass, re-reading from the start. If it rejects the table the
	 * arrays stay unread; if it accepts, every index in them is now proven
	 * in range, which is the invariant the scan leans on. */
	cur.pos = 0;
	if (!ufw_ac_load(&cur, &ac))
		goto out;

	hits = xalloc(ac.pattern_count, sizeof(*hits));
	if (!hits)
		goto out;

	/* Walk the decoded table over a real buffer — the table bytes
	 * themselves, capped at the reassembly budget the kernel would never
	 * exceed. If load's bounds-checking missed an index, the traversal is
	 * where it reads out of bounds, and ASan is watching the tight arrays. */
	scan_len = size > UFW_STREAM_FUZZ_CAP ? UFW_STREAM_FUZZ_CAP : (__u32)size;
	ufw_ac_scan(&ac, (const __u8 *)data, scan_len, hits);

	/* Drive the per-condition decision, including arm 4's bounded naive
	 * search, with offsets and depths derived from each pattern so the window
	 * arithmetic (offset+depth, i+pattern_len<=end) is exercised too. */
	for (t = 0; t < 2; t++) {
		__u32 i;

		for (i = 0; i < ac.pattern_count; i++) {
			const struct ufw_ac_pattern *p = &ac.patterns[i];
			__u32 offset = t == 0 ? 0u : (i & 0x3fu);
			__u32 depth  = t == 0 ? 0u : ((i * 7u) & 0xffu);

			(void)ufw_ac_content_matches(p->bytes, p->len, p->nocase,
						     offset, depth, hits[i],
						     (const __u8 *)data, scan_len);
		}
	}

out:
	free(ac.patterns);
	free(ac.states);
	free(ac.transitions);
	free(ac.outputs);
	free(hits);
	return 0;
}
