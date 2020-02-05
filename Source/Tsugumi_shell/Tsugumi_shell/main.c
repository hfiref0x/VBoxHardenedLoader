/*

Tsugumi shellcode project

File		: main.c
Modified	: Wed Jan 29 2020, 22:30

*/

#include <ntddk.h>
#include <intrin.h>
#include "Tsugumi.h"

/*
    disable C6320 "Exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER.
                   This might mask exceptions that were not intended to be handled."
*/
#pragma warning(disable: 6320)

NTSTATUS DriverMain(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    volatile const PMAPPED_CODE_DATA    ShellEnvBlock =
        (PMAPPED_CODE_DATA)(ULONG_PTR)0x1337c0de1cedc01a; // Magic pattern to search and replace
    volatile PVOID  fnptr = (PVOID)&DriverUnload; // hack to prevent unreferenced code elimination

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(fnptr);

    if (ShellEnvBlock->fInititialized != 1) // We should use a fast mutex here, but we can't properly initialize it in shell code.
    {
        ShellEnvBlock->fInititialized = 1;
        ShellEnvBlock->PsSetLoadImageNotifyRoutine(PsImageHandler); // PsImageHandler referenced by relative addressing. No need to fix.
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    ShellEnvBlock->IofCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

VOID DriverUnload(
    _In_ PDRIVER_OBJECT     DriverObject
)
{
    volatile const PMAPPED_CODE_DATA    ShellEnvBlock =
        (PMAPPED_CODE_DATA)(ULONG_PTR)0x1337c0de1cedc01a; // Magic pattern to search and replace

    LARGE_INTEGER   t;
    UNICODE_STRING  sl;
    WCHAR           sl_name[23] = {
        L'\\', L'D', L'o', L's', L'D', L'e', L'v', L'i',L'c', L'e', L's',
        L'\\', L'P', L'R', L'O', L'C', L'E', L'X', L'P',L'1', L'5', L'2', L'\0'
    };
    // \DosDevices\PROCEXP152

    ShellEnvBlock->PsRemoveLoadImageNotifyRoutine(PsImageHandler);
    ShellEnvBlock->RtlInitUnicodeString(&sl, sl_name);
    ShellEnvBlock->IoDeleteSymbolicLink(&sl);
    ShellEnvBlock->IoDeleteDevice(DriverObject->DeviceObject);

    t.QuadPart = -100000ll; // 0.1 sec
    while (ShellEnvBlock->iNotifyCounter != 0)
        ShellEnvBlock->KeDelayExecutionThread(KernelMode, FALSE, &t);

    ShellEnvBlock->KeDelayExecutionThread(KernelMode, FALSE, &t);
}

NTSTATUS HandleUserMemWrite(
    _In_ PMAPPED_CODE_DATA  ShellEnvBlock,
    _In_ PVOID              SrcAddress,
    _In_ PVOID              DestAddress,
    _In_ ULONG              Size)
{
    PMDL        mdl;
    NTSTATUS    status = STATUS_SUCCESS;

    mdl = ShellEnvBlock->IoAllocateMdl(DestAddress, Size, FALSE, FALSE, NULL);
    if (mdl == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    __try {
        if ((ULONG_PTR)DestAddress >= 0x7FFFFFFFFFFFull)
            return STATUS_CONFLICTING_ADDRESSES;
        
        ShellEnvBlock->MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        // DestAddress = ShellEnvBlock->MmGetSystemAddressForMdlSafe(mdl, HighPagePriority | MdlMappingNoExecute);

        //  begin MmGetSystemAddressForMdlSafe copy-paste
        if (mdl->MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL)) {
            DestAddress = mdl->MappedSystemVa;
        }
        else {
            DestAddress = ShellEnvBlock->MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached,
                NULL, FALSE, HighPagePriority | MdlMappingNoExecute);
        }
        //  end MmGetSystemAddressForMdlSafe copy-paste

        if (DestAddress != NULL) {
            status = ShellEnvBlock->MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
            __movsb((PUCHAR)DestAddress, (const UCHAR*)SrcAddress, Size); // intrinsic
            ShellEnvBlock->MmUnmapLockedPages(DestAddress, mdl);
            ShellEnvBlock->MmUnlockPages(mdl);
        }
        else {
            status = STATUS_ACCESS_VIOLATION;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_ACCESS_VIOLATION;
    }
    
    ShellEnvBlock->IoFreeMdl(mdl);
    return status;
}

VOID PsImageHandler(
    _In_ PUNICODE_STRING    FullImageName,
    _In_ HANDLE             ProcessId,
    _In_ PIMAGE_INFO        ImageInfo
)
{
    volatile const PMAPPED_CODE_DATA    ShellEnvBlock =
        (PMAPPED_CODE_DATA)(ULONG_PTR)0x1337c0de1cedc01a; // Magic pattern to search and replace

    InterlockedIncrement(&ShellEnvBlock->iNotifyCounter);

    PBINARY_PATCH_BLOCK     PatchChains;
    ULONG                   c, l = 0;
    WCHAR                   TargetDllName[11] = {
        L'V', L'B', L'o', L'x', L'D', L'D', L'.', L'd',L'l', L'l', L'\0'
    };

    while ((FullImageName != NULL) && (ImageInfo != NULL) && (ShellEnvBlock->PsGetCurrentProcessId() == ProcessId))
    {
        if ((FullImageName->Buffer == NULL) || (FullImageName->Length == 0))
            break;

        for (c = 0; c < (ULONG)FullImageName->Length / 2; ++c)
            if (FullImageName->Buffer[c] == '\\')
                l = c + 1;

        if (ShellEnvBlock->_wcsnicmp(&FullImageName->Buffer[l], TargetDllName, wcslen(TargetDllName)) == 0) { // wcslen got inlined
            l = 0;
            PatchChains = (PBINARY_PATCH_BLOCK)&ShellEnvBlock->ConfigurationData;

            while (l + BLOCK_DATA_OFFSET < ShellEnvBlock->ConfigurationDataSize) {
                if (PatchChains->DataLength != 0)
                    // HandleUserMemWrite called by relative addressing. No need to fix.
                    HandleUserMemWrite(ShellEnvBlock, PatchChains->Data,
                    (PVOID)((ULONG_PTR)ImageInfo->ImageBase + PatchChains->VirtualOffset), PatchChains->DataLength);
                l += BLOCK_DATA_OFFSET + PatchChains->DataLength;
                PatchChains = (PBINARY_PATCH_BLOCK)((ULONG_PTR)PatchChains + BLOCK_DATA_OFFSET + PatchChains->DataLength);
            }
        }

        break;
    }

    InterlockedDecrement(&ShellEnvBlock->iNotifyCounter);
}
