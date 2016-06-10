/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2016
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.61
*
*  DATE:        06 June 2016
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
static PKEY_VALUE_PARTIAL_INFORMATION    PatchChains_VBoxDD = NULL;
static PKEY_VALUE_PARTIAL_INFORMATION    PatchChains_VBoxVMM = NULL;

static const WCHAR DDname[] = L"VBoxDD.dll";
static const WCHAR VMMname[] = L"VBoxVMM.dll";

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
* TsmiApplyPatch
*
* Purpose:
*
* Iterate through patch chains and apply them all.
*
*/
NTSTATUS TsmiApplyPatchChains(
    _In_ PKEY_VALUE_PARTIAL_INFORMATION PatchChains,
    _In_ PIMAGE_INFO ImageInfo
)
{
    NTSTATUS              ntStatus = STATUS_UNSUCCESSFUL;
    PBINARY_PATCH_BLOCK   Chains;
    ULONG                 l = 0;

    if (ImageInfo == NULL)
        return ntStatus;

    KeWaitForSingleObject(&g_PatchChainsLock, Executive, KernelMode, FALSE, NULL);

    if (PatchChains != NULL) {
        l = 0;
        Chains = (PBINARY_PATCH_BLOCK)&PatchChains->Data[0];
        while (l + BLOCK_DATA_OFFSET < PatchChains->DataLength) {
            if (Chains->DataLength != 0) {
                if ((Chains->VirtualOffset < ImageInfo->ImageSize) &&
                    (Chains->VirtualOffset + Chains->DataLength < ImageInfo->ImageSize))
                {
                    ntStatus = TsmiHandleMemWrite(Chains->Data, (PVOID)((ULONG_PTR)ImageInfo->ImageBase + Chains->VirtualOffset), Chains->DataLength);
                }
            }
            l += BLOCK_DATA_OFFSET + Chains->DataLength;
            Chains = (PBINARY_PATCH_BLOCK)((ULONG_PTR)Chains + BLOCK_DATA_OFFSET + Chains->DataLength);
        }
#ifdef _DEBUGMSG
        DbgPrint("[TSMI] Patch apply complete\n");
#endif
    }

    KeReleaseMutex(&g_PatchChainsLock, FALSE);

    return ntStatus;
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
    ULONG  c, l = 0;

    PAGED_CODE();

    if ((FullImageName == NULL) || (ImageInfo == NULL) || (PsGetCurrentProcessId() != ProcessId))
        return;

    if ((FullImageName->Buffer == NULL) || (FullImageName->Length == 0))
        return;

    for (c = 0; c < (ULONG)FullImageName->Length / sizeof(WCHAR); c++)
        if (FullImageName->Buffer[c] == '\\')
            l = c + 1;

    if (_wcsnicmp(&FullImageName->Buffer[l], DDname, wcslen(DDname)) == 0) {
        if (NT_SUCCESS(TsmiApplyPatchChains(PatchChains_VBoxDD, ImageInfo))) {
#ifdef _DEBUGMSG
            DbgPrint("[TSMI]  DD patched\n");
#endif
        }
    }

    if (_wcsnicmp(&FullImageName->Buffer[l], VMMname, wcslen(VMMname)) == 0) {
        if (NT_SUCCESS(TsmiApplyPatchChains(PatchChains_VBoxVMM, ImageInfo))) {
#ifdef _DEBUGMSG
            DbgPrint("[TSMI]  MM patched\n");
#endif
        }
    }
}

/*
* TsmiListPatchChains
*
* Purpose:
*
* Output patch chains. DebugMsg only build.
*
*/
VOID TsmiListPatchChains(
    _In_ PKEY_VALUE_PARTIAL_INFORMATION PatchChains
)
{
    ULONG                  l = 0;
    PBINARY_PATCH_BLOCK    Chains;

    DbgPrint("[TSMI] Patch chains -> %p\n", PatchChains);

    if (PatchChains == NULL)
        return;

    l = 0;
    Chains = (PBINARY_PATCH_BLOCK)&PatchChains->Data[0];

    DbgPrint("[TSMI] Chains->DataLength=%lx\n", PatchChains->DataLength);

    while (l + BLOCK_DATA_OFFSET < PatchChains->DataLength) {
        if (Chains->DataLength != 0) {
            DbgPrint("[TSMI] Chain->Offset: %lx, Chain->DataLength: %lx\n", Chains->VirtualOffset, Chains->DataLength);
        }
        l += BLOCK_DATA_OFFSET + Chains->DataLength;
        Chains = (PBINARY_PATCH_BLOCK)((ULONG_PTR)Chains + BLOCK_DATA_OFFSET + Chains->DataLength);
    }
}

/*
* TsmiReadPatchChains
*
* Purpose:
*
* Read specified chains value from registry.
*
*/
NTSTATUS TsmiReadPatchChains(
    _In_ HANDLE sKey,
    _In_ PUNICODE_STRING ParamName,
    _In_ PVOID *ParamBuffer,
    _In_ ULONG *ChainsLength
)
{
    KEY_VALUE_PARTIAL_INFORMATION   keyinfo;
    NTSTATUS                        status;
    ULONG                           bytesIO = 0;

    if (ChainsLength == NULL)
        return STATUS_INVALID_PARAMETER_4;

    status = ZwQueryValueKey(sKey, ParamName, KeyValuePartialInformation, &keyinfo, sizeof(KEY_VALUE_PARTIAL_INFORMATION), &bytesIO);
    if (NT_SUCCESS(status))
        return STATUS_BUFFER_TOO_SMALL; // The key value is empty. It should not success with zero-length buffer if there are some data;

    if ((status != STATUS_BUFFER_TOO_SMALL) && (status != STATUS_BUFFER_OVERFLOW))
        return STATUS_INVALID_PARAMETER; // we got unexpected return

    // bytesIO contains key value data length
    *ChainsLength = bytesIO;
    *ParamBuffer = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTagPriority(PagedPool, (SIZE_T)bytesIO, TSUGUMI_TAG, NormalPoolPriority);
    if (*ParamBuffer == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

#ifdef _DEBUGMSG
    DbgPrint("[TSMI] ChainsLength=%lx\n", *ChainsLength);
#endif

    RtlSecureZeroMemory(*ParamBuffer, bytesIO);
    status = ZwQueryValueKey(sKey, ParamName, KeyValuePartialInformation, *ParamBuffer, bytesIO, &bytesIO);
#ifdef _DEBUGMSG
    if (NT_SUCCESS(status)) {
        TsmiListPatchChains(*ParamBuffer);
    }
#endif
    return status;
}

/*
* TsmiCopyPatchChainsData
*
* Purpose:
*
* Copy/Refresh patch chains data to global variable.
*
*/
VOID TsmiCopyPatchChainsData(
    _In_ PVOID *PatchChains,
    _In_ PVOID Chains,
    _In_ ULONG ChainsLength
)
{
    if ((PatchChains == NULL) || (Chains == NULL) || (ChainsLength == 0))
        return;

    KeWaitForSingleObject(&g_PatchChainsLock, Executive, KernelMode, FALSE, NULL);

    if (*PatchChains != NULL) {
        ExFreePoolWithTag(*PatchChains, TSUGUMI_TAG);
        *PatchChains = NULL;
    }

    *PatchChains = (PVOID)ExAllocatePoolWithTagPriority(PagedPool, ChainsLength, TSUGUMI_TAG, NormalPoolPriority);
    if (*PatchChains) {
        RtlSecureZeroMemory(*PatchChains, ChainsLength);
        RtlCopyMemory(*PatchChains, Chains, ChainsLength);
    }

    KeReleaseMutex(&g_PatchChainsLock, FALSE);
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
    PKEY_VALUE_PARTIAL_INFORMATION  tmpChains;
    HANDLE                          hKey = NULL;
    NTSTATUS                        status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING                  uStr;
    OBJECT_ATTRIBUTES               ObjectAttributes;
    ULONG                           ChainsLength;

    RtlInitUnicodeString(&uStr, TSUGUMI_PARAMS);
    InitializeObjectAttributes(&ObjectAttributes, &uStr, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwOpenKey(&hKey, KEY_READ, &ObjectAttributes);
    if (!NT_SUCCESS(status))
        return status;

    do {

#ifdef _DEBUGMSG
        DbgPrint("[TSMI] TsmiLoadParameters(%ws)\n", DDname);
#endif
        ChainsLength = 0;
        tmpChains = NULL;
        RtlInitUnicodeString(&uStr, DDname);
        status = TsmiReadPatchChains(hKey, &uStr, &tmpChains, &ChainsLength);
        if (NT_SUCCESS(status)) {
            if (tmpChains != NULL) {
                TsmiCopyPatchChainsData(&PatchChains_VBoxDD, tmpChains, ChainsLength);
                ExFreePoolWithTag(tmpChains, TSUGUMI_TAG);
            }
        }

#ifdef _DEBUGMSG
        DbgPrint("[TSMI] TsmiLoadParameters(%ws)\n", VMMname);
#endif
        ChainsLength = 0;
        tmpChains = NULL;
        RtlInitUnicodeString(&uStr, VMMname);
        status = TsmiReadPatchChains(hKey, &uStr, &tmpChains, &ChainsLength);
        if (NT_SUCCESS(status)) {
            if (tmpChains != NULL) {
                TsmiCopyPatchChainsData(&PatchChains_VBoxVMM, tmpChains, ChainsLength);
                ExFreePoolWithTag(tmpChains, TSUGUMI_TAG);
            }
        }

    } while (cond);

    ZwClose(hKey);
    hKey = NULL;

#ifdef _DEBUGMSG
    DbgPrint("[TSMI] TsmiLoadParameters=%lx\n", status);
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
                        DbgPrint("[TSMI] DevioctlDispatch:NotifySet=%lx\n", g_NotifySet);
#endif
                    }
                }
            }
#ifdef _DEBUGMSG
            else {
                DbgPrint("[TSMI] DevioctlDispatch:Notify already installed\n");
            }
#endif
            bytesIO = g_NotifySet;
            break;

        case TSUGUMI_IOCTL_MONITOR_STOP:

            bytesIO = 0;

            if (g_NotifySet) {
                status = PsRemoveLoadImageNotifyRoutine(TsmiPsImageHandler);
                if (NT_SUCCESS(status)) {
                    g_NotifySet = FALSE;
                    bytesIO = 1;
                }
            }
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
    DbgPrint("[TSMI] DriverInitialize:NotifySet=%lx\n", g_NotifySet);
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
