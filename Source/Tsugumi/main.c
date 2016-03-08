/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2016
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.10
*
*  DATE:        02 Mar 2016
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include <ntddk.h>
#include "main.h"

//#define _DEBUGMSG

#pragma warning(disable: 6102) //"Using %s from failed call at line %s"

//synchronization mutex
static KMUTEX      g_PatchChainsLock;

//notify flag 
static BOOLEAN     g_NotifySet;

//data buffer
static PKEY_VALUE_PARTIAL_INFORMATION    PatchChains = NULL;

/*
* TsmiHandleMemWrite
*
* Purpose:
*
* Patch vbox dll in memory.
*
* Warning: potential BSOD-generator due to nonstandard way of loading, take care with patch offsets.
*
*/
NTSTATUS TsmiHandleMemWrite(
	_In_ PVOID SrcAddress,
	_In_ PVOID DestAddress,
	_In_ ULONG Size
	)
{
	PMDL        mdl;
	NTSTATUS    status = STATUS_SUCCESS;

	PAGED_CODE();

	mdl = IoAllocateMdl(DestAddress, Size, FALSE, FALSE, NULL);
	if (mdl == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	if (DestAddress >= MmSystemRangeStart)
		if (!MmIsAddressValid(DestAddress)) {
			return STATUS_ACCESS_VIOLATION;
		}
	MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
	DestAddress = MmGetSystemAddressForMdlSafe(mdl, HighPagePriority);
	if (DestAddress != NULL) {
		status = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
		__movsb((PUCHAR)DestAddress, (const UCHAR *)SrcAddress, Size);
		MmUnmapLockedPages(DestAddress, mdl);
		MmUnlockPages(mdl);
	}
	else {
		status = STATUS_ACCESS_VIOLATION;
	}
	
	IoFreeMdl(mdl);
	return status;
}

/*
* TsmiPsImageHandler
*
* Purpose:
*
* Notify to catch VirtualBox dlls loading.
*
*/
VOID TsmiPsImageHandler(
    _In_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,               
    _In_ PIMAGE_INFO ImageInfo
    )
{
	static const WCHAR    DDname[] = L"VBoxDD.dll";
	ULONG                 c, l=0;
	PBINARY_PATCH_BLOCK   Chains;

	PAGED_CODE();

	if ((FullImageName == NULL) || (ImageInfo == NULL) || (PsGetCurrentProcessId() != ProcessId))
		return;

	if ((FullImageName->Buffer == NULL) || (FullImageName->Length == 0))
		return;

	for (c = 0; c < (ULONG)FullImageName->Length / sizeof(WCHAR); c++)
		if (FullImageName->Buffer[c] == '\\')
			l = c + 1;

	if (_wcsnicmp(&FullImageName->Buffer[l], DDname, wcslen(DDname)) == 0) {

		KeWaitForSingleObject(&g_PatchChainsLock, Executive, KernelMode, FALSE, NULL);

		if (PatchChains != NULL) {
			l = 0;
			Chains = (PBINARY_PATCH_BLOCK)&PatchChains->Data[0];
			while (l + BLOCK_DATA_OFFSET < PatchChains->DataLength) {
				if (Chains->DataLength != 0) {
					if ((Chains->VirtualOffset < ImageInfo->ImageSize) &&
						(Chains->VirtualOffset + Chains->DataLength < ImageInfo->ImageSize))
					{
						TsmiHandleMemWrite(Chains->Data, (PVOID)((ULONG_PTR)ImageInfo->ImageBase + Chains->VirtualOffset), Chains->DataLength);
					}
				}
				l += BLOCK_DATA_OFFSET + Chains->DataLength;
				Chains = (PBINARY_PATCH_BLOCK)((ULONG_PTR)Chains + BLOCK_DATA_OFFSET + Chains->DataLength);
			}
			DbgPrint("VBoxDD patched");
		}

		KeReleaseMutex(&g_PatchChainsLock, FALSE);

	}
}

/*
* TsmiLoadParameters
*
* Purpose:
*
* Read parameters from registry.
*
*/
NTSTATUS TsmiLoadParameters(
	VOID
	)
{
	UCHAR                           cond = 0;
	KEY_VALUE_PARTIAL_INFORMATION   keyinfo;
	PKEY_VALUE_PARTIAL_INFORMATION  tmp = NULL;
	HANDLE                          hKey = NULL;
	NTSTATUS                        status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING                  uStr;
	OBJECT_ATTRIBUTES               ObjectAttributes;
	ULONG                           bytesIO = 0, ChainsLength = 0;

	RtlInitUnicodeString(&uStr, TSUGUMI_PARAMS);
	InitializeObjectAttributes(&ObjectAttributes, &uStr, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwOpenKey(&hKey, KEY_READ, &ObjectAttributes);
	if (!NT_SUCCESS(status))
		return status;

	do {
		RtlInitUnicodeString(&uStr, TSUGUMI_PATCHDATA);
		bytesIO = 0;

		status = ZwQueryValueKey(hKey, &uStr, KeyValuePartialInformation, &keyinfo, sizeof(KEY_VALUE_PARTIAL_INFORMATION), &bytesIO);
		if (NT_SUCCESS(status)) {
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		if ((status != STATUS_BUFFER_TOO_SMALL) && (status != STATUS_BUFFER_OVERFLOW)) {
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		ChainsLength = bytesIO;
		tmp = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTagPriority(PagedPool, ChainsLength, TSUGUMI_TAG, NormalPoolPriority);
		if (tmp == NULL) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		RtlSecureZeroMemory(tmp, ChainsLength);
		status = ZwQueryValueKey(hKey, &uStr, KeyValuePartialInformation, tmp, ChainsLength, &bytesIO);

	} while (cond);

	ZwClose(hKey);
	hKey = NULL;

	//copy new value
	if ((NT_SUCCESS(status)) && (tmp != NULL) && (ChainsLength != 0)) {

		KeWaitForSingleObject(&g_PatchChainsLock, Executive, KernelMode, FALSE, NULL);

		if (PatchChains != NULL) {
			ExFreePoolWithTag(PatchChains, TSUGUMI_TAG);
			PatchChains = NULL;
		}
		PatchChains = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTagPriority(PagedPool, ChainsLength, TSUGUMI_TAG, NormalPoolPriority);
		if (PatchChains) {
			RtlCopyMemory(PatchChains, tmp, ChainsLength);
		}

		KeReleaseMutex(&g_PatchChainsLock, FALSE);

#ifdef _DEBUGMSG
		DbgPrint("Copied\n");
#endif
	}


	if (tmp != NULL)
		ExFreePoolWithTag(tmp, TSUGUMI_TAG);
#ifdef _DEBUGMSG
	DbgPrint("TsmiLoadParameters=%lx\n", status);
#endif
	return status;
}

/*
* DevioctlDispatch
*
* Purpose:
*
* IRP_MJ_DEVICE_CONTROL dispatch.
*
*/
NTSTATUS DevioctlDispatch(
	_In_ struct _DEVICE_OBJECT *DeviceObject,
	_Inout_ struct _IRP *Irp
	)
{
	NTSTATUS                status = STATUS_SUCCESS;
	PIO_STACK_LOCATION      stack;
	ULONG_PTR               bytesIO = 0;

	UNREFERENCED_PARAMETER(DeviceObject);

	stack = IoGetCurrentIrpStackLocation(Irp);

	if (stack != NULL) {
		switch (stack->Parameters.DeviceIoControl.IoControlCode) {
		case TSUGUMI_IOCTL_REFRESH_LIST:

			status = TsmiLoadParameters();
			if (g_NotifySet == FALSE) {
				if (NT_SUCCESS(status)) {
					status = PsSetLoadImageNotifyRoutine(TsmiPsImageHandler);
					if (NT_SUCCESS(status)) {
						g_NotifySet = TRUE;
						
#ifdef _DEBUGMSG
						DbgPrint("DevioctlDispatch:NotifySet=%lx\n", g_NotifySet);
#endif
					}
				}
			}
#ifdef _DEBUGMSG
			else {
				DbgPrint("DevioctlDispatch:Notify already installed\n");
			}
#endif
			bytesIO = g_NotifySet;
			break;
		default:
			status = STATUS_INVALID_PARAMETER;
		};
	}
	else {
		status = STATUS_INTERNAL_ERROR;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = bytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

/*
* UnsupportedDispatch
*
* Purpose:
*
* Unused IRP_MJ_* dispatch.
*
*/
NTSTATUS UnsupportedDispatch(
	_In_ struct _DEVICE_OBJECT *DeviceObject,
	_Inout_ struct _IRP *Irp
	)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_NOT_SUPPORTED;
}

/*
* CreateCloseDispatch
*
* Purpose:
*
* IRP_MJ_CREATE/IRP_MJ_CLOSE dispatch.
*
*/
NTSTATUS CreateCloseDispatch(
	_In_ struct _DEVICE_OBJECT *DeviceObject,
	_Inout_ struct _IRP *Irp
	)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

/*
* DriverInitialize
*
* Purpose:
*
* Driver main.
*
*/
NTSTATUS DriverInitialize(
	_In_  struct _DRIVER_OBJECT *DriverObject,
	_In_  PUNICODE_STRING RegistryPath
	)
{
	NTSTATUS        status;
	UNICODE_STRING  SymLink, DevName;
	PDEVICE_OBJECT  devobj;
	ULONG           t;

	//RegistryPath is NULL
	UNREFERENCED_PARAMETER(RegistryPath);
	
	KeInitializeMutex(&g_PatchChainsLock, 0);

	RtlInitUnicodeString(&DevName, TSUGUMI_DEV_OBJECT);
	status = IoCreateDevice(DriverObject, 0, &DevName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, TRUE, &devobj);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	RtlInitUnicodeString(&SymLink, TSUGUMI_SYM_LINK);
	status = IoCreateSymbolicLink(&SymLink, &DevName);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(devobj);
		return status;
	}
	
	devobj->Flags |= DO_BUFFERED_IO;
	for (t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
		DriverObject->MajorFunction[t] = &UnsupportedDispatch;

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &DevioctlDispatch;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = &CreateCloseDispatch;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = &CreateCloseDispatch;
	DriverObject->DriverUnload = NULL; 

	devobj->Flags &= ~DO_DEVICE_INITIALIZING;

	g_NotifySet = FALSE;
	status = TsmiLoadParameters();
	if (NT_SUCCESS(status)) {
		status = PsSetLoadImageNotifyRoutine(TsmiPsImageHandler);
		if (NT_SUCCESS(status)) {
			g_NotifySet = TRUE;
		}
	}
#ifdef _DEBUGMSG
	DbgPrint("DriverInitialize:NotifySet=%lx\n", g_NotifySet);
#endif
	return STATUS_SUCCESS;
}

/*
* DriverEntry
*
* Purpose:
*
* Tsugumi entry point.
*
*/
NTSTATUS DriverEntry(
  _In_  struct _DRIVER_OBJECT *DriverObject,
  _In_  PUNICODE_STRING RegistryPath
)
{
	UNICODE_STRING  drvName;

	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	RtlInitUnicodeString(&drvName, TSUGUMI_DRV_OBJECT);
	return IoCreateDriver(&drvName, &DriverInitialize);
}
