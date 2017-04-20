/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.82
*
*  DATE:        20 Apr 2017
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include <ntddk.h>
#include "main.h"

#pragma warning(disable: 6102) //"Using %s from failed call at line %s"

VBOX_PATCH g_VBoxDD;

// Notify flag 
BOOLEAN     g_NotifySet;

// Data buffer
static const WCHAR DDname[] = L"VBoxDD.dll";


/*
* TsmiHandleMemWrite
*
* Purpose:
*
* Patch vbox dll in memory.
*
* Warning: If compiled not in ReleaseSigned configuration this function is a
* potential BSOD-generator due to nonstandard way of loading, take care with patch offsets.
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
#ifdef _DEBUGMSG
        DbgPrint("[TSMI] Failed to create MDL at write\n");
#endif
        return STATUS_INSUFFICIENT_RESOURCES;
    }

#ifdef _SIGNED_BUILD
    __try {
#endif //_SIGNED_BUILD

        if (DestAddress >= MmSystemRangeStart)
            if (!MmIsAddressValid(DestAddress)) {
#ifdef _DEBUGMSG
                DbgPrint("[TSMI] Invalid address\n");
#endif //_DEBUGMSG
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

#ifdef _SIGNED_BUILD
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_ACCESS_VIOLATION;
#ifdef _DEBUGMSG
        DbgPrint("[TSMI] MmProbeAndLockPages failed at write DestAddress = %p\n", DestAddress);
#endif //_DEBUGMSG
    }
#endif //_SIGNED_BUILD

    IoFreeMdl(mdl);
    return status;
}

/*
* TsmiPatchImage
*
* Purpose:
*
* Iterate through patch chains and apply them all.
*
*/
NTSTATUS TsmiPatchImage(
    _In_ VBOX_PATCH *PatchInfo,
    _In_ PIMAGE_INFO ImageInfo
)
{
    NTSTATUS                        ntStatus = STATUS_UNSUCCESSFUL;
    PBINARY_PATCH_BLOCK             Chains;
    PKEY_VALUE_PARTIAL_INFORMATION  PatchChains;
    ULONG                           l = 0;

    PAGED_CODE();

    if ((ImageInfo == NULL) || (PatchInfo == NULL))
        return ntStatus;

    KeWaitForSingleObject(&PatchInfo->Lock, Executive, KernelMode, FALSE, NULL);

    PatchChains = PatchInfo->Chains;

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
        DbgPrint("[TSMI] Image patch complete\n");
#endif //_DEBUGMSG
    }

    KeReleaseMutex(&PatchInfo->Lock, FALSE);

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

    //
    // Patch VBoxDD image.
    //
    if (_wcsnicmp(&FullImageName->Buffer[l], DDname, wcslen(DDname)) == 0) {
        if (NT_SUCCESS(TsmiPatchImage(&g_VBoxDD, ImageInfo))) {
#ifdef _DEBUGMSG
            DbgPrint("[TSMI]  DD patched\n");
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
    _In_ KEY_VALUE_PARTIAL_INFORMATION *PatchChains
)
{
    ULONG                  l = 0;
    PBINARY_PATCH_BLOCK    Chains;

    PAGED_CODE();

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
    _In_ VBOX_PATCH *PatchInfo
)
{
    KEY_VALUE_PARTIAL_INFORMATION       keyinfo;
    ULONG                               ChainsLength = 0, bytesIO;
    NTSTATUS                            status;

    PAGED_CODE();

    if (sKey == NULL)
        return STATUS_INVALID_PARAMETER_1;

    if (ParamName == NULL)
        return STATUS_INVALID_PARAMETER_2;

    if (PatchInfo == NULL)
        return STATUS_INVALID_PARAMETER_3;

    status = ZwQueryValueKey(sKey, ParamName, KeyValuePartialInformation, &keyinfo, sizeof(KEY_VALUE_PARTIAL_INFORMATION), &ChainsLength);
    if (NT_SUCCESS(status)) {
        return STATUS_BUFFER_TOO_SMALL; // The key value is empty. It should not success with zero-length buffer if there are some data;
    }

    if ((status != STATUS_BUFFER_TOO_SMALL) && (status != STATUS_BUFFER_OVERFLOW)) {
        return status;
    }

    //
    // Allocate buffer for data with given size
    //
    PatchInfo->Chains = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTagPriority(PagedPool,
        (SIZE_T)ChainsLength, TSUGUMI_TAG, NormalPoolPriority);
    if (PatchInfo->Chains == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;


#ifdef _DEBUGMSG
    DbgPrint("[TSMI] ChainsLength=%lx\n", ChainsLength);
#endif //_DEBUGMSG

    RtlSecureZeroMemory(PatchInfo->Chains, ChainsLength);
    status = ZwQueryValueKey(sKey, ParamName, KeyValuePartialInformation, PatchInfo->Chains, ChainsLength, &bytesIO);
    if (NT_SUCCESS(status)) {
        PatchInfo->ChainsLength = ChainsLength;
#ifdef _DEBUGMSG
        TsmiListPatchChains(PatchInfo->Chains);
#endif //_DEBUGMSG
    }

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
    _In_ VBOX_PATCH *Src,
    _In_ VBOX_PATCH *Dst
)
{
    PAGED_CODE();

    if ((Src == NULL) || (Dst == NULL))
        return;

    if ((Src->Chains == NULL) || (Src->ChainsLength == 0))
        return;

    KeWaitForSingleObject(&Dst->Lock, Executive, KernelMode, FALSE, NULL);

    if (Dst->Chains != NULL) {
        ExFreePoolWithTag(Dst->Chains, TSUGUMI_TAG);
        Dst->Chains = NULL;
        Dst->ChainsLength = 0;
    }

    Dst->Chains = Src->Chains;
    Dst->ChainsLength = Src->ChainsLength;

    KeReleaseMutex(&Dst->Lock, FALSE);
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
    UCHAR                cond = 0;
    HANDLE               hKey = NULL;
    NTSTATUS             status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING       uStr;
    OBJECT_ATTRIBUTES    ObjectAttributes;
    VBOX_PATCH           tempPatch;

    PAGED_CODE();

    RtlInitUnicodeString(&uStr, TSUGUMI_PARAMS);
    InitializeObjectAttributes(&ObjectAttributes, &uStr, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwOpenKey(&hKey, KEY_READ, &ObjectAttributes);
    if (!NT_SUCCESS(status))
        return status;

    do {
        tempPatch.Chains = NULL;
        tempPatch.ChainsLength = 0;

        RtlInitUnicodeString(&uStr, DDname);
        status = TsmiReadPatchChains(hKey, &uStr, &tempPatch);
        if (NT_SUCCESS(status)) {
            TsmiCopyPatchChainsData(&tempPatch, &g_VBoxDD);
        }
        else {
            // VBoxDD must be always patched so return error if no patch data found.
            status = STATUS_UNSUCCESSFUL;
            break;
        }

    } while (cond);

    ZwClose(hKey);
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

    PAGED_CODE();

    stack = IoGetCurrentIrpStackLocation(Irp);

    if (stack != NULL) {
        switch (stack->Parameters.DeviceIoControl.IoControlCode) {
        case TSUGUMI_IOCTL_REFRESH_LIST:

#ifdef _DEBUGMSG
            DbgPrint("[TSMI] DevioctlDispatch:TSUGUMI_IOCTL_REFRESH_LIST");
#endif //_DEBUGMSG

            status = TsmiLoadParameters();
            if (g_NotifySet == FALSE) {
                if (NT_SUCCESS(status)) {
                    status = PsSetLoadImageNotifyRoutine(TsmiPsImageHandler);
                    if (NT_SUCCESS(status)) {
                        g_NotifySet = TRUE;

#ifdef _DEBUGMSG
                        DbgPrint("[TSMI] DevioctlDispatch:NotifySet=%lx\n", g_NotifySet);
#endif //_DEBUGMSG

                    }
                }
            }

#ifdef _DEBUGMSG
            else {
                DbgPrint("[TSMI] DevioctlDispatch:Notify already installed\n");
            }
#endif //_DEBUGMSG

            bytesIO = g_NotifySet;
            break;

        case TSUGUMI_IOCTL_MONITOR_STOP:

            bytesIO = 0;

#ifdef _DEBUGMSG
            DbgPrint("[TSMI] DevioctlDispatch:TSUGUMI_IOCTL_MONITOR_STOP");
#endif //_DEBUGMSG


            if (g_NotifySet) {
                status = PsRemoveLoadImageNotifyRoutine(TsmiPsImageHandler);
                if (NT_SUCCESS(status)) {
                    g_NotifySet = FALSE;
#ifdef _DEBUGMSG
                    DbgPrint("[TSMI] DevioctlDispatch:NotifySet=%lx\n", g_NotifySet);
#endif //_DEBUGMSG
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

    PAGED_CODE();

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

    PAGED_CODE();

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/*
* DriverUnload
*
* Purpose:
*
* Driver unload procedure.
*
*/
VOID DriverUnload(
    _In_  struct _DRIVER_OBJECT *DriverObject
)
{
    PAGED_CODE();

    UNICODE_STRING  SymLink;

#ifdef _DEBUGMSG
    DbgPrint("[TSMI] Unload, DrvObj = %p\n", DriverObject);
#endif

    if (g_NotifySet) {
        PsRemoveLoadImageNotifyRoutine(TsmiPsImageHandler);
    }

    KeWaitForSingleObject(&g_VBoxDD.Lock, Executive, KernelMode, FALSE, NULL);

    if (g_VBoxDD.Chains) {
        ExFreePoolWithTag(g_VBoxDD.Chains, TSUGUMI_TAG);
        g_VBoxDD.Chains = NULL;
        g_VBoxDD.ChainsLength = 0;
    }

    KeReleaseMutex(&g_VBoxDD.Lock, FALSE);

    RtlInitUnicodeString(&SymLink, TSUGUMI_SYM_LINK);
    IoDeleteSymbolicLink(&SymLink);
    IoDeleteDevice(DriverObject->DeviceObject);
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

    //RegistryPath is unused
    UNREFERENCED_PARAMETER(RegistryPath);

    g_NotifySet = FALSE;

    g_VBoxDD.Chains = NULL;
    g_VBoxDD.ChainsLength = 0;
    KeInitializeMutex(&g_VBoxDD.Lock, 0);

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

#ifndef _SIGNED_BUILD
    DriverObject->DriverUnload = NULL;
    devobj->Flags &= ~DO_DEVICE_INITIALIZING;
#else
    DriverObject->DriverUnload = &DriverUnload;
    status = TsmiLoadParameters();
    if (NT_SUCCESS(status)) {
        status = PsSetLoadImageNotifyRoutine(TsmiPsImageHandler);
        if (NT_SUCCESS(status)) {
            g_NotifySet = TRUE;
        }
    }
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
#ifndef _SIGNED_BUILD
    UNICODE_STRING  drvName;

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&drvName, TSUGUMI_DRV_OBJECT);
    return IoCreateDriver(&drvName, &DriverInitialize);
#else
    return DriverInitialize(DriverObject, RegistryPath);
#endif
}
