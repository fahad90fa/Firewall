# Deploying on Windows

## The signing requirement, first

A kernel-mode driver on 64-bit Windows will not load unless Microsoft has signed
it. Not "should be signed" — will not load.

An EV certificate is necessary but **not sufficient**: it authenticates your
*submission* to the Hardware Dev Center, and Microsoft's countersignature is what
the kernel accepts. Plan for the submission round trip before scheduling a
rollout.

```powershell
# Development: loads only in test-signing mode.
build\windows\driver_signing.ps1 -DriverPath x64\Release\ufw.sys -TestSign
bcdedit /set testsigning on     # then reboot

# Production: sign, package, submit.
build\windows\driver_signing.ps1 -DriverPath x64\Release\ufw.sys -Thumbprint <EV>
# → signed\ufw.cab → https://partner.microsoft.com/dashboard/hardware
```

The script **refuses** to production-sign a driver with no Static Driver Verifier
log. SDV catches the IRQL violations and lock imbalances that bugcheck a
production machine under load, days later, on hardware you cannot attach a
debugger to. Signing an unanalysed WFP callout is how that ships.

## Building

Needs the WDK matching your Visual Studio.

```
make -C kernel\windows            # debug
make -C kernel\windows analyze    # Code Analysis
make -C kernel\windows sdv        # Static Driver Verifier — slow, required
make -C kernel\windows release    # depends on both of the above
```

`release` depends on `analyze` and `sdv` deliberately. They are not optional
steps that happen to be in a Makefile.

## Installing

```powershell
msiexec /i unified-firewall.msi
```

The MSI installs the driver as a **boot-start** service, so it is filtering
before anything else on the machine has a chance to talk, and the daemon service
depends on it. Starting the daemon first would mean it comes up, fails its
handshake, and exits — a confusing first-boot experience the dependency simply
prevents.

Like the Linux package, the MSI installs example policies under `examples\` and
activates **none** of them.

## Choosing a policy

```powershell
copy "C:\Program Files\Unified Firewall\examples\default_allow.yaml" ^
     "C:\ProgramData\UnifiedFirewall\policies\active.yaml"
ufwctl debug mode monitor --yes
# collect the inventory, write the rules, then switch to default_deny.yaml
```

See `policies/base/default_allow.yaml` for the full sequence and why cold-starting
default-deny on an uncatalogued fleet is a bad trade.

## Verifying

```powershell
sc query ufw          # the driver
sc query ufwd         # the daemon
ufwctl status
```

```powershell
# Which WFP filters are actually installed:
netsh wfp show filters file=filters.xml
```

The driver installs its filters in its own sublayer (`UFW_SUBLAYER_GUID`) at
weight `0xF000`. Having a dedicated sublayer means an unrelated product's filters
cannot silently override a policy decision, and ours cannot silently override
theirs — whichever wins is a visible, deliberate choice rather than an accident
of installation order.

## The layer split, if you are reading the filter dump

You will see filters at ALE **and** at the IP packet layers, and this is not
duplication.

WFP layers fire in a different relative order per direction:

```
outbound:  ALE_AUTH_CONNECT  →  OUTBOUND_IPPACKET
inbound:   INBOUND_IPPACKET  →  ALE_AUTH_RECV_ACCEPT
```

So the two families *partition* the traffic rather than layering. Every TCP and
UDP flow is decided at ALE, where the process is available. The IP packet layers
carry the same rules scoped to what ALE never sees — ICMP and the other portless
protocols. No flow is decided twice, so the firing order stops mattering.

`kernel/windows/inc/callout.h` has the full argument.

## When something is wrong

**The driver will not start.** `sc query ufw` reports error 577 when the
signature is not accepted. On a test-signed build, confirm test-signing mode is
on and the machine was rebooted.

**The daemon exits at startup.** It could not open `\\.\UnifiedFirewall`. Either
the driver is not running, or the caller is not an administrator — the device ACL
admits only SYSTEM and Administrators.

**Connections fail with no log entry.** Something else is filtering. `netsh wfp
show netevents` shows which filter blocked; if it is not in our sublayer, it is
not us.

**Emergency.** `ufwctl debug mode emergency-allow --yes` stops all filtering
without unloading the driver, and is recorded at critical severity.
