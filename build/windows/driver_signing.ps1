<#
.SYNOPSIS
    Sign the Unified Firewall WFP callout driver for production.

.DESCRIPTION
    A kernel-mode driver on 64-bit Windows will not load unless it is signed by
    a certificate chaining to a Microsoft-issued cross-certificate — since
    Windows 10 1607, that means the driver must be submitted to the Hardware
    Dev Center and signed by Microsoft. An EV certificate alone is not enough:
    it authenticates the *submission*, and Microsoft's signature is what the
    kernel actually accepts.

    This script does the part that can be automated: verify the driver is
    build-clean, sign it with the EV certificate, and produce the CAB the
    Dev Center expects. The submission itself is a manual step, and so is
    retrieving the countersigned binary.

    Running this on a machine without an EV certificate in the store is a
    normal outcome during development. Use `-TestSign` instead, which produces
    a driver that loads only on a machine in test-signing mode — deliberately,
    so a test-signed driver cannot be mistaken for a shippable one.

.PARAMETER DriverPath
    Path to ufw.sys.

.PARAMETER Thumbprint
    SHA-1 thumbprint of the EV code-signing certificate.

.PARAMETER TestSign
    Sign with a locally generated test certificate instead. The result loads
    only after `bcdedit /set testsigning on` and a reboot.

.EXAMPLE
    .\driver_signing.ps1 -DriverPath x64\Release\ufw.sys -TestSign

.EXAMPLE
    .\driver_signing.ps1 -DriverPath x64\Release\ufw.sys -Thumbprint ABCD...
#>

[CmdletBinding(DefaultParameterSetName = 'Production')]
param(
    [Parameter(Mandatory = $true)]
    [string]$DriverPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Production')]
    [string]$Thumbprint,

    [Parameter(Mandatory = $true, ParameterSetName = 'Test')]
    [switch]$TestSign,

    [string]$TimestampUrl = 'http://timestamp.digicert.com',

    [string]$OutputDir = 'signed'
)

$ErrorActionPreference = 'Stop'

function Find-SignTool {
    # The WDK installs several; the newest is the one that knows about current
    # signing requirements. Hard-coding a version is how a script starts failing
    # after an SDK update.
    $roots = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
        "${env:ProgramFiles}\Windows Kits\10\bin"
    )
    $candidates = foreach ($root in $roots) {
        if (Test-Path $root) {
            Get-ChildItem -Path $root -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -match '\\x64\\' }
        }
    }
    $tool = $candidates | Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $tool) {
        throw "signtool.exe not found. Install the Windows SDK or WDK."
    }
    return $tool.FullName
}

function Assert-BuildQuality {
    param([string]$Path)

    # A driver that was never run through Code Analysis or SDV should not be
    # signed. Those tools find IRQL violations and lock imbalances — the class
    # of bug that bugchecks a production machine under load, days later, with
    # no way to attach a debugger. Signing an unanalysed driver is how that
    # ships.
    $dvl = Join-Path (Split-Path $Path -Parent) 'ufw.DVL.XML'
    if (-not (Test-Path $dvl)) {
        Write-Warning @"
No Driver Verification Log (ufw.DVL.XML) beside the driver.

Static Driver Verifier has not been run, or its results were not exported.
The Hardware Dev Center requires the DVL for submission, and more importantly
SDV is what catches the IRQL and locking mistakes that turn into a bugcheck on
somebody else's machine.

Run:  make -C kernel\windows sdv
"@
        if (-not $TestSign) {
            throw "Refusing to production-sign a driver with no DVL. Use -TestSign for development."
        }
    }
}

# --- main ------------------------------------------------------------------

if (-not (Test-Path $DriverPath)) {
    throw "Driver not found: $DriverPath"
}

$signtool = Find-SignTool
Write-Host "Using $signtool"

Assert-BuildQuality -Path $DriverPath

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$signed = Join-Path $OutputDir (Split-Path $DriverPath -Leaf)
Copy-Item $DriverPath $signed -Force

if ($TestSign) {
    Write-Host "Test-signing (development only)"

    $certName = 'UnifiedFirewallTest'
    $cert = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Subject -eq "CN=$certName" } |
        Select-Object -First 1

    if (-not $cert) {
        Write-Host "Creating a test certificate"
        $cert = New-SelfSignedCertificate `
            -Subject "CN=$certName" `
            -Type CodeSigningCert `
            -CertStoreLocation Cert:\CurrentUser\My `
            -KeyUsage DigitalSignature `
            -KeyLength 2048
        # Into the trusted roots, so the local machine will accept it once
        # test-signing mode is on.
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store 'Root', 'LocalMachine'
        $store.Open('ReadWrite')
        $store.Add($cert)
        $store.Close()
    }

    & $signtool sign /v /fd SHA256 /sha1 $cert.Thumbprint $signed
    if ($LASTEXITCODE -ne 0) { throw "signtool failed with $LASTEXITCODE" }

    Write-Host @"

Test-signed. This driver loads ONLY on a machine in test-signing mode:

    bcdedit /set testsigning on
    (reboot)

It will not load on a production machine, which is the point: a test-signed
driver must not be mistakable for a shippable one.
"@
    exit 0
}

# --- production ------------------------------------------------------------

Write-Host "Signing with EV certificate $Thumbprint"

# SHA-256, with a timestamp. Without the timestamp the signature stops
# validating when the certificate expires, which turns a working deployment
# into a machine that cannot load its firewall on the next reboot.
& $signtool sign /v /fd SHA256 /td SHA256 /tr $TimestampUrl /sha1 $Thumbprint $signed
if ($LASTEXITCODE -ne 0) { throw "signtool failed with $LASTEXITCODE" }

& $signtool verify /v /pa $signed
if ($LASTEXITCODE -ne 0) { throw "signature verification failed" }

# --- CAB for Dev Center submission ----------------------------------------

$cabDir = Join-Path $OutputDir 'cab'
New-Item -ItemType Directory -Force -Path $cabDir | Out-Null
Copy-Item $signed $cabDir -Force

$inf = Join-Path (Split-Path $DriverPath -Parent) 'ufw.inf'
if (Test-Path $inf) {
    Copy-Item $inf $cabDir -Force
} else {
    Write-Warning "No ufw.inf beside the driver; the submission needs one."
}

$ddf = Join-Path $OutputDir 'ufw.ddf'
@"
.OPTION EXPLICIT
.Set CabinetFileCountThreshold=0
.Set FolderFileCountThreshold=0
.Set FolderSizeThreshold=0
.Set MaxCabinetSize=0
.Set MaxDiskFileCount=0
.Set MaxDiskSize=0
.Set CompressionType=MSZIP
.Set Cabinet=on
.Set Compress=on
.Set DestinationDir=ufw
.Set CabinetNameTemplate=ufw.cab
.Set DiskDirectoryTemplate=$OutputDir
"$cabDir\ufw.sys"
"$cabDir\ufw.inf"
"@ | Set-Content -Path $ddf -Encoding ASCII

& makecab /f $ddf
if ($LASTEXITCODE -ne 0) { throw "makecab failed with $LASTEXITCODE" }

$cab = Join-Path $OutputDir 'ufw.cab'
& $signtool sign /v /fd SHA256 /td SHA256 /tr $TimestampUrl /sha1 $Thumbprint $cab
if ($LASTEXITCODE -ne 0) { throw "signing the CAB failed with $LASTEXITCODE" }

Write-Host @"

Signed and packaged: $cab

The driver is NOT yet loadable on a production machine. Submit the CAB to the
Hardware Dev Center for attestation signing:

    https://partner.microsoft.com/dashboard/hardware

Microsoft's countersignature is what the kernel accepts; the EV signature above
only authenticates the submission. Download the countersigned package when the
submission completes and ship that.
"@
