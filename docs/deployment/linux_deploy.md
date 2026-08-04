# Deploying on Linux

## What gets installed

| | |
| --- | --- |
| `ufw.ko` | The netfilter module, via DKMS |
| eBPF objects | Pinned under `/sys/fs/bpf/ufw` |
| `ufwd` | systemd service |
| `ufwctl` | `/usr/local/bin` |

## From a package

```sh
build/linux/package.sh deb        # or rpm
sudo dpkg -i unified-firewall_0.1.0_amd64.deb
```

The package installs the machinery and **no policy**, and the daemon will not
start until you name one. That is deliberate: a firewall package that activates a
policy of its own choosing either picks something permissive — security theatre —
or something restrictive, which takes the machine off the network in the middle
of an `apt upgrade`.

## From source

```sh
make && sudo make install
make kernel-linux
sudo insmod kernel/linux/ufw.ko
```

## DKMS

The package registers the module with DKMS so it is rebuilt against every kernel
the machine boots. Without it, a routine kernel update leaves a module that will
not load — and a firewall that fails after a routine update is a firewall that
gets uninstalled rather than fixed.

```sh
dkms status unified-firewall
```

The module is fail-closed, so "did not load" means "not filtering", not "blocking
everything". A machine that cannot load its firewall should still be reachable so
somebody can fix it. `ufwctl status` says so in its first line, and the daemon
refuses to start.

## Choosing a policy

**If this fleet's egress has never been catalogued, do not start with
default-deny.** Switching cold produces an outage and a rollback, and the
rollback is what people remember.

```sh
# Phase one: permissive, monitoring.
sudo cp /usr/share/unified-firewall/policies/base/default_allow.yaml \
        /etc/unified-firewall/policies/active.yaml
sudo ufwctl debug mode monitor --yes

# Collect the inventory.
ufwctl logs --action allow --group-by application

# Phase two: write the allow rules that inventory implies, then:
sudo cp .../default_deny.yaml /etc/unified-firewall/policies/active.yaml
sudo ufwctl debug mode enforce --yes
```

`policies/base/default_allow.yaml` documents this sequence at the top of the
file, and every `alert` rule in it marks a category that should be gone before
phase two.

## Starting

```sh
sudo systemctl enable --now ufw-ebpf unified-firewall
ufwctl status
```

Two units on purpose. Loading the eBPF programs and running the daemon fail
differently and should be diagnosable separately: a daemon that will not start
because the fast path failed is a confusing symptom, whereas `ufw-ebpf.service`
in a failed state is not.

## Capabilities

The daemon runs with `CAP_NET_ADMIN` (install policy, manage netfilter) and
`CAP_SYS_PTRACE` (read `/proc/<pid>/exe` for identity). The eBPF loader
additionally needs `CAP_BPF` and `CAP_SYS_ADMIN`.

Everything else is denied by the unit's sandbox — `ProtectSystem=strict`,
`MemoryDenyWriteExecute=yes`, `RestrictAddressFamilies` to the four it uses.
`ProtectKernelModules` is deliberately *not* set: the daemon talks to one.

## eBPF pinning

The `unified-firewall-ebpf.service` unit runs `ufwd --load-ebpf` before the
daemon starts, and `--unload-ebpf` on stop. Loading shells out to `bpftool`
rather than linking libbpf: reaching `bpf(2)` from Rust means libc or
hand-written per-architecture syscall stubs, and `bpftool` ships with the
kernel's own tooling, is versioned with it, and reports verifier rejections in
the form the kernel meant them. Install `linux-tools` (Debian) or `bpftool`
(Fedora) or the unit fails at boot saying so.

Removing a pin does not detach a running program — that is the module's
business, and an unload that also detached would leave the machine unfiltered
during a package upgrade.

Maps are pinned under `/sys/fs/bpf/ufw` so they outlive the loader. Restarting
the daemon should not flush the flow table and re-decide every established
connection.

```sh
sudo bpftool map show pinned /sys/fs/bpf/ufw/flows
sudo bpftool prog show pinned /sys/fs/bpf/ufw/ingress
```

## Verifying it works

```sh
ufwctl status                 # health, revision, counters
ufwctl rules list             # what is installed
ufwctl debug stats            # kernel counters
ufwctl logs --follow          # decisions as they happen
```

Two counters worth watching. `identity_queries_timed_out` climbing means the
daemon is not answering fast enough and flows are being decided without identity.
`log_events_dropped` climbing means the log path is behind — the decisions are
still correct, but the record is incomplete.

## When something is wrong

**The daemon exits at startup.** Almost always the module is not loaded. `dmesg |
grep ufw`, then `modprobe ufw`.

**Everything is blocked.** The default is deny and the policy did not name what
you expected. `ufwctl policy explain <policy> tcp:<addr>:<port>:out` says which
rule decided and why.

**A rule never fires.** Most often the stage trap: a catch-all at the packet
layer pre-empts every identity rule beneath it whatever the priority. `ufwctl
policy validate` reports it as `W0300`.

**Emergency.** `sudo ufwctl debug mode emergency-allow --yes` stops all
filtering without unloading anything. It is recorded at critical severity. This
exists because a firewall that cannot be turned off during an outage gets turned
off by uninstalling it, which loses the logs too.
