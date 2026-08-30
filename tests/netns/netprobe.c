/*
 * netprobe — the minimal privileged helper the enforcement-conformance test
 * needs, and nothing more.
 *
 * The Rust harness compiles a policy, extracts the emitted nftables ruleset,
 * loads it into a throwaway network namespace and then has to answer one
 * question per probe: *did a real packet get through, or did the kernel drop
 * it?* That question cannot be answered from user space without two operations
 * Rust's standard library does not expose — bringing an interface up (an
 * ioctl) and observing a connect that the firewall may silently drop — so they
 * live here, in ~60 lines of C compiled on demand with the same `cc` the
 * kernel module already requires. The alternative, a `libc` dependency on the
 * test crate, would pull a crate into `cargo build --workspace` and break the
 * zero-dependency property the whole project rests on. A build-time-only C
 * helper does not.
 *
 * Two subcommands:
 *
 *   netprobe up            Bring `lo` up in the current namespace. A fresh
 *                          netns has `lo` present but DOWN, and nothing on
 *                          127.0.0.1 works until it is up. Done with a raw
 *                          SIOCSIFFLAGS ioctl so the helper needs no `ip`
 *                          binary (absent on minimal images; present in CI).
 *
 *   netprobe connect PORT  Bind+listen on 127.0.0.1:PORT, then connect to it
 *                          from this same process with a 2s deadline. Exit 0 if
 *                          the handshake completes (the ruleset ALLOWED the
 *                          flow), 1 if it times out or is refused (the ruleset
 *                          DROPPED it). No accept() is needed: the kernel
 *                          completes the handshake into the listen backlog, so
 *                          a successful connect is proof the packets crossed
 *                          both the output and input hooks.
 *
 * Exit codes are the whole interface; it prints nothing on success.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int bring_lo_up(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return 2;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) != 0) return 3;
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(s, SIOCSIFFLAGS, &ifr) != 0) return 4;
    close(s);
    return 0;
}

/* Returns 0 if the loopback connect to PORT completes, 1 if it does not. */
static int probe_connect(int port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) return 2;
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(ls, (struct sockaddr *)&addr, sizeof addr) != 0) return 3;
    if (listen(ls, 1) != 0) return 4;

    int cs = socket(AF_INET, SOCK_STREAM, 0);
    if (cs < 0) return 5;
    int flags = fcntl(cs, F_GETFL, 0);
    fcntl(cs, F_SETFL, flags | O_NONBLOCK);

    int rc = connect(cs, (struct sockaddr *)&addr, sizeof addr);
    if (rc == 0) return 0; /* immediate connect (unlikely, but allowed) */
    if (errno != EINPROGRESS) return 1;

    fd_set wf;
    FD_ZERO(&wf);
    FD_SET(cs, &wf);
    struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
    rc = select(cs + 1, NULL, &wf, NULL, &tv);
    if (rc <= 0) return 1; /* timed out: the SYN was dropped */

    int soerr = 0;
    socklen_t len = sizeof soerr;
    if (getsockopt(cs, SOL_SOCKET, SO_ERROR, &soerr, &len) != 0) return 1;
    return soerr == 0 ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "up") == 0) {
        return bring_lo_up();
    }
    if (argc >= 3 && strcmp(argv[1], "connect") == 0) {
        int port = atoi(argv[2]);
        if (port <= 0 || port > 65535) return 64;
        return probe_connect(port);
    }
    return 64; /* usage */
}
