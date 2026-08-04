/*
 * Unified Firewall — DriverEntry, unload, and IOCTL dispatch.
 *
 * # Initialisation order
 *
 *   device -> DPI -> stream -> identity -> logging -> IPC -> WFP
 *
 * WFP last, and that is the only ordering constraint that really matters:
 * from the moment the callouts are registered, classify can be called on any
 * processor. A subsystem that is not ready then either has to tolerate being
 * called before it is initialised — a class of bug that shows up as a rare
 * bugcheck under load — or WFP comes last. WFP comes last.
 *
 * Teardown is the exact reverse, with the filter removal before the callout
 * deregistration, because FwpsCalloutUnregisterByKey fails with
 * STATUS_DEVICE_BUSY while filters still reference the callout.
 *
 * # The device ACL
 *
 * The control device is created with an explicit security descriptor
 * admitting only SYSTEM and Administrators. Without one, the default DACL on
 * a device created by a driver permits far more than it should, and every
 * IOCTL here either changes what the machine may talk to or reports on it.
 * The IOCTL access flags (FILE_WRITE_ACCESS on the mutating codes) are a
 * second, independent check — the two fail differently, which is the point.
 */

#include "../inc/driver.h"
#include "../inc/callout.h"

UFW_DRIVER_STATE g_ufw;

DRIVER_INITIALIZE DriverEntry;
static DRIVER_UNLOAD UfwUnload;
static DRIVER_DISPATCH UfwDispatchCreateClose;
static DRIVER_DISPATCH UfwDispatchDeviceControl;

/*
 * D:P(A;;GA;;;SY)(A;;GA;;;BA)
 *
 * Protected (no inherited ACEs), granting all access to Local System and to
 * the Administrators group, and to nobody else. An unprivileged process
 * cannot open the device at all, so the IOCTL handlers never see one.
 */
DECLARE_CONST_UNICODE_STRING(g_deviceSddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

/* {b1f3a5e2-...} — the device class GUID, required when a security
 * descriptor is supplied to IoCreateDeviceSecure. */
static const GUID g_deviceClassGuid = {
	0xb1f3a5e2, 0x4c8d, 0x4f17,
	{ 0x9a, 0x3b, 0x7e, 0x21, 0x0c, 0x64, 0xd8, 0x53 }
};

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT driverObject,
		     _In_ PUNICODE_STRING registryPath)
{
	UNICODE_STRING deviceName, symbolicLink;
	PDEVICE_OBJECT device = NULL;
	NTSTATUS status;

	UNREFERENCED_PARAMETER(registryPath);

	RtlZeroMemory(&g_ufw, sizeof(g_ufw));
	g_ufw.mode = UFW_MODE_ENFORCE;

	driverObject->DriverUnload = UfwUnload;
	driverObject->MajorFunction[IRP_MJ_CREATE] = UfwDispatchCreateClose;
	driverObject->MajorFunction[IRP_MJ_CLOSE] = UfwDispatchCreateClose;
	driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = UfwDispatchDeviceControl;

	RtlInitUnicodeString(&deviceName, UFW_DEVICE_NAME);
	RtlInitUnicodeString(&symbolicLink, UFW_SYMBOLIC_LINK);

	status = IoCreateDeviceSecure(driverObject, 0, &deviceName,
				      FILE_DEVICE_UNKNOWN,
				      FILE_DEVICE_SECURE_OPEN, FALSE,
				      &g_deviceSddl, &g_deviceClassGuid,
				      &device);
	if (!NT_SUCCESS(status))
		return status;

	status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
	if (!NT_SUCCESS(status))
		goto failDevice;

	g_ufw.deviceObject = device;

	status = UfwDpiInitialize();
	if (!NT_SUCCESS(status))
		goto failLink;

	status = UfwStreamInitialize();
	if (!NT_SUCCESS(status))
		goto failDpi;

	status = UfwIdentityInitialize();
	if (!NT_SUCCESS(status))
		goto failStream;

	status = UfwLogInitialize();
	if (!NT_SUCCESS(status))
		goto failIdentity;

	status = UfwIpcInitialize(device);
	if (!NT_SUCCESS(status))
		goto failLog;

	/* Last. From here, classify can be called. */
	status = UfwWfpInitialize(device);
	if (!NT_SUCCESS(status))
		goto failIpc;

	device->Flags &= ~DO_DEVICE_INITIALIZING;
	DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
		   "ufw: loaded, ABI %d, fail-closed until a policy is installed\n",
		   UFW_ABI_REVISION);
	return STATUS_SUCCESS;

failIpc:
	UfwIpcShutdown();
failLog:
	UfwLogShutdown();
failIdentity:
	UfwIdentityShutdown();
failStream:
	UfwStreamShutdown();
failDpi:
	UfwDpiShutdown();
failLink:
	IoDeleteSymbolicLink(&symbolicLink);
failDevice:
	IoDeleteDevice(device);
	return status;
}

static VOID UfwUnload(_In_ PDRIVER_OBJECT driverObject)
{
	UNICODE_STRING symbolicLink;

	UNREFERENCED_PARAMETER(driverObject);

	/* First: no new classifications after this returns, and every filter
	 * is removed before its callout is deregistered. */
	UfwWfpShutdown();

	UfwIpcShutdown();
	UfwLogShutdown();
	UfwIdentityShutdown();
	UfwStreamShutdown();
	UfwDpiShutdown();
	UfwPolicyFlush();

	RtlInitUnicodeString(&symbolicLink, UFW_SYMBOLIC_LINK);
	IoDeleteSymbolicLink(&symbolicLink);

	if (g_ufw.deviceObject)
		IoDeleteDevice(g_ufw.deviceObject);

	DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL, "ufw: unloaded\n");
}

static NTSTATUS UfwDispatchCreateClose(_In_ PDEVICE_OBJECT deviceObject,
				       _In_ PIRP irp)
{
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

	UNREFERENCED_PARAMETER(deviceObject);

	/*
	 * Track whether the daemon is attached. The identity path uses this
	 * to stop enqueueing queries nobody will answer, which is what keeps
	 * a daemon crash from filling the event queue with requests and then
	 * dropping the log events behind them.
	 */
	if (stack->MajorFunction == IRP_MJ_CREATE)
		InterlockedIncrement(&g_ufw.daemonAttached);
	else
		InterlockedDecrement(&g_ufw.daemonAttached);

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

BOOLEAN UfwDaemonAttached(VOID)
{
	return InterlockedCompareExchange(&g_ufw.daemonAttached, 0, 0) > 0;
}

static NTSTATUS UfwDispatchDeviceControl(_In_ PDEVICE_OBJECT deviceObject,
					 _In_ PIRP irp)
{
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
	ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
	ULONG inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
	ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
	PVOID buffer = irp->AssociatedIrp.SystemBuffer;
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	ULONG_PTR written = 0;

	UNREFERENCED_PARAMETER(deviceObject);

	switch (code) {
	case UFW_IOCTL_HELLO: {
		UFW_HELLO_REPLY *reply = (UFW_HELLO_REPLY *)buffer;
		UFW_POLICY_TABLE *table;
		KIRQL irql;

		if (outLen < sizeof(*reply)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		RtlZeroMemory(reply, sizeof(*reply));
		reply->abiRevision = UFW_ABI_REVISION;
		reply->driverVersion = UFW_DRIVER_VERSION;
		reply->capabilities = UFW_CAP_IDENTITY | UFW_CAP_DPI |
				      UFW_CAP_STREAM | UFW_CAP_IPV6 |
				      UFW_CAP_SCHEDULE;

		table = UfwPolicyAcquire(&irql);
		reply->installedRevision = table ? table->revision : 0;
		UfwPolicyRelease(irql);

		written = sizeof(*reply);
		status = STATUS_SUCCESS;
		break;
	}

	case UFW_IOCTL_INSTALL_POLICY: {
		const UFW_INSTALL_HEADER *header = (const UFW_INSTALL_HEADER *)buffer;

		if (inLen < sizeof(*header)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		/*
		 * The declared payload size and the actual buffer must agree
		 * exactly. Longer leaves trailing bytes; shorter leaves
		 * filters uninitialised. Either is a desynchronisation between
		 * the daemon and the driver, and this is the one place to
		 * catch it — everything downstream trusts the count.
		 */
		if (inLen - sizeof(*header) != header->payloadBytes) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		if (header->abiRevision != UFW_ABI_REVISION) {
			status = STATUS_REVISION_MISMATCH;
			break;
		}
		status = UfwPolicyInstall(header,
					  (const UINT8 *)buffer + sizeof(*header),
					  header->payloadBytes);
		break;
	}

	case UFW_IOCTL_INSTALL_SIGNATURES:
		status = UfwDpiInstall((const UINT8 *)buffer, inLen);
		break;

	case UFW_IOCTL_SET_MODE: {
		UINT8 mode;

		if (inLen < sizeof(UINT8)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		mode = *(const UINT8 *)buffer;
		if (mode > UFW_MODE_EMERGENCY_ALLOW) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		InterlockedExchange(&g_ufw.mode, (LONG)mode);
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_WARNING_LEVEL,
			   "ufw: enforcement mode is now %u\n", mode);
		status = STATUS_SUCCESS;
		break;
	}

	case UFW_IOCTL_GET_STATS:
		if (outLen < sizeof(UFW_STATS)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		RtlCopyMemory(buffer, &g_ufw.stats, sizeof(UFW_STATS));
		written = sizeof(UFW_STATS);
		status = STATUS_SUCCESS;
		break;

	case UFW_IOCTL_FLUSH_POLICY:
		UfwPolicyFlush();
		UfwIdentityFlush();
		UfwStreamFlush();
		/* With no table installed the classifier fails closed. That is
		 * what "flush" means here: remove every rule, leaving the
		 * default action, which is deny. */
		status = STATUS_SUCCESS;
		break;

	case UFW_IOCTL_IDENTITY_RESPONSE:
		if (inLen < sizeof(UFW_IDENTITY_RESPONSE)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		UfwIdentityDeliver((const UFW_IDENTITY_RESPONSE *)buffer, inLen);
		status = STATUS_SUCCESS;
		break;

	case UFW_IOCTL_AWAIT_EVENT:
		/* Pended, not completed here. UfwIpcDispatch takes ownership
		 * of the IRP and completes it when an event is available. */
		return UfwIpcDispatch(deviceObject, irp);

	default:
		break;
	}

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = written;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}
