/*
 * libFuzzer entry point for the protocol decoders.
 *
 * The in-tree fuzzer in `daemon/tests/dpi_decoder_tests.rs` runs on every
 * `cargo test` and is a tripwire: deterministic, twenty thousand mutants, no
 * coverage feedback. This is the other half — a coverage-guided campaign that
 * runs for hours and finds what a blind mutator does not.
 *
 * Both matter. The tripwire catches the regression somebody pushes on a
 * Tuesday. The campaign catches the bug that needs a nine-byte prefix nobody
 * would guess.
 *
 *   clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *         -fno-sanitize-recover=all \
 *         -I ../kernel/linux/inc -o fuzz-linux decoders.c
 *   ./fuzz-linux corpus/ -max_len=65536 -jobs=8
 *
 * and for the Windows decoders:
 *
 *   clang -g -O1 -fsanitize=fuzzer,address,undefined -DUFW_ABI_CHECK \
 *         -DUFW_FUZZ_WINDOWS -I ../kernel/windows/inc -o fuzz-windows decoders.c
 *
 * A crash writes the input to `crash-<sha1>`; feed that file to the binary
 * directly to reproduce, and add it to `corpus/` once fixed so it stays fixed.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "dpi_decoders.h"

#ifdef UFW_FUZZ_WINDOWS
#define UFW_DECODED_T   UFW_DECODED
#define UFW_SET         UfwDecodedSet
#define UFW_DNS         UfwDecodeDns
#define UFW_HTTP        UfwDecodeHttp
#define UFW_TLS         UfwDecodeTls
#define UFW_SSH         UfwDecodeSsh
#define UFW_ENTROPY     UfwEntropyCentibits
#define UFW_IDENTIFY    UfwDpiIdentify
#else
#define UFW_DECODED_T   struct ufw_decoded
#define UFW_SET         decoded_set
#define UFW_DNS         decode_dns
#define UFW_HTTP        decode_http
#define UFW_TLS         decode_tls
#define UFW_SSH         decode_ssh
#define UFW_ENTROPY     entropy_centibits
#define UFW_IDENTIFY    ufw_dpi_identify
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
        UFW_DECODED_T decoded;
        uint8_t l7;

        /* The first byte selects the protocol, so one corpus exercises all
         * four decoders and the fuzzer can learn to flip it. The alternative —
         * four binaries — splits the coverage feedback four ways. */
        if (size < 1)
                return 0;
        l7 = data[0] % 5;
        data++;
        size--;

        /* The engine never sees more than the reassembly budget, so fuzzing
         * past it would explore a path that does not exist in production. */
        if (size > 32 * 1024)
                size = 32 * 1024;

        memset(&decoded, 0, sizeof(decoded));
        UFW_SET(&decoded, UFW_FIELD_PAYLOAD_LEN, (uint32_t)size);

        switch (l7) {
        case 1: UFW_HTTP(&decoded, data, (uint32_t)size); break;
        case 2: UFW_TLS(&decoded, data, (uint32_t)size); break;
        case 3: UFW_DNS(&decoded, data, (uint32_t)size); break;
        case 4: UFW_SSH(&decoded, data, (uint32_t)size); break;
        default: break;
        }

        /* Entropy and identification read the same bytes with their own
         * arithmetic, and are cheap enough to run on every input. entropy
         * takes its 256-entry scratch buffer from the caller: the kernel hands
         * in a per-CPU one to stay off the module stack, the fuzzer a local. */
        {
                uint32_t counts[256];
                (void)UFW_ENTROPY(data, (uint32_t)size, counts);
        }
        (void)UFW_IDENTIFY(data, size, 443);
        return 0;
}
