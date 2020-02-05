/*

Tsugumi shellcode project

File		: Tsugumi.h
Modified	: Wed Jan 29 2020, 22:30

*/

#pragma once

#ifndef _TSUGUMI_H_
#define _TSUGUMI_H_

#include <ntddk.h>

typedef struct _BINARY_PATCH_BLOCK {
    ULONG   VirtualOffset;
    UCHAR   DataLength;
    UCHAR   Data[1];
} BINARY_PATCH_BLOCK, * PBINARY_PATCH_BLOCK;

#define BLOCK_DATA_OFFSET       (ULONG_PTR)(&((PBINARY_PATCH_BLOCK)0)->Data)

typedef _Check_return_ int(__cdecl* PFN_wcsnicmp)(_In_reads_or_z_(_MaxCount) const wchar_t* _Str1, _In_reads_or_z_(_MaxCount) const wchar_t* _Str2, _In_ size_t _MaxCount);

typedef _IRQL_requires_max_(DISPATCH_LEVEL) PMDL (*PFN_IoAllocateMdl)(
    _In_opt_ __drv_aliasesMem PVOID VirtualAddress,
    _In_ ULONG Length,
    _In_ BOOLEAN SecondaryBuffer,
    _In_ BOOLEAN ChargeQuota,
    _Inout_opt_ PIRP Irp
);

typedef _IRQL_requires_max_(DISPATCH_LEVEL) VOID (*PFN_IoFreeMdl)(
    PMDL Mdl
);

typedef HANDLE (*PFN_PsGetCurrentProcessId)(
    VOID
);

typedef _Must_inspect_result_ _IRQL_requires_max_(DISPATCH_LEVEL) NTSTATUS (*PFN_MmProtectMdlSystemAddress)(
    _In_ PMDL MemoryDescriptorList,
    _In_ ULONG NewProtect
);

typedef _IRQL_requires_max_(DISPATCH_LEVEL) VOID (*PFN_MmUnmapLockedPages)(
    _In_ PVOID BaseAddress,
    _Inout_ PMDL MemoryDescriptorList
);

typedef _IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS (*PFN_PsSetLoadImageNotifyRoutine)(
    _In_ PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
);

typedef _IRQL_requires_max_(DISPATCH_LEVEL) VOID (*PFN_MmUnlockPages)(
    _Inout_ PMDL MemoryDescriptorList
);

typedef _IRQL_requires_max_(DISPATCH_LEVEL)
_At_(MemoryDescriptorList->StartVa + MemoryDescriptorList->ByteOffset,
    _Field_size_bytes_opt_(MemoryDescriptorList->ByteCount)) // Esp:823  Esp:829
    VOID (*PFN_MmProbeAndLockPages)(
        _Inout_ PMDL MemoryDescriptorList,
        _In_ KPROCESSOR_MODE AccessMode,
        _In_ LOCK_OPERATION Operation
    );

typedef _Post_writable_byte_size_(MemoryDescriptorList->ByteCount)
_When_(AccessMode == KernelMode, _IRQL_requires_max_(DISPATCH_LEVEL))
_When_(AccessMode == UserMode, _Maybe_raises_SEH_exception_ _IRQL_requires_max_(APC_LEVEL) _Post_notnull_)
_At_(MemoryDescriptorList->MappedSystemVa,
    _Post_writable_byte_size_(MemoryDescriptorList->ByteCount)) // Esp:829
    _Must_inspect_result_
    _Success_(return != NULL)
    PVOID (*PFN_MmMapLockedPagesSpecifyCache)(
        _Inout_ PMDL MemoryDescriptorList,
        _In_ __drv_strictType(KPROCESSOR_MODE / enum _MODE, __drv_typeConst)
        KPROCESSOR_MODE AccessMode,
        _In_ __drv_strictTypeMatch(__drv_typeCond) MEMORY_CACHING_TYPE CacheType,
        _In_opt_ PVOID RequestedAddress,
        _In_     ULONG BugCheckOnFailure,
        _In_     ULONG Priority  // MM_PAGE_PRIORITY logically OR'd with MdlMapping*
    );

typedef _IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS (*PFN_PsSetLoadImageNotifyRoutine)(
    _In_ PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
);

typedef _IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS (*PFN_PsRemoveLoadImageNotifyRoutine)(
    _In_ PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
);

typedef _IRQL_requires_max_(DISPATCH_LEVEL)
VOID (FASTCALL *PFN_IofCompleteRequest)(
    _In_ PIRP Irp,
    _In_ CCHAR PriorityBoost
);

typedef _IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS (*PFN_KeDelayExecutionThread)(
    _In_ KPROCESSOR_MODE WaitMode,
    _In_ BOOLEAN Alertable,
    _In_ PLARGE_INTEGER Interval
);

typedef _IRQL_requires_max_(DISPATCH_LEVEL)
_At_(DestinationString->Buffer, _Post_equal_to_(SourceString))
_At_(DestinationString->Length, _Post_equal_to_(_String_length_(SourceString) * sizeof(WCHAR)))
_At_(DestinationString->MaximumLength, _Post_equal_to_((_String_length_(SourceString) + 1) * sizeof(WCHAR)))
VOID (NTAPI *PFN_RtlInitUnicodeString)(
    _Out_ PUNICODE_STRING DestinationString,
    _In_opt_z_ __drv_aliasesMem PCWSTR SourceString
);

typedef _IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS (*PFN_IoDeleteSymbolicLink)(
    _In_ PUNICODE_STRING SymbolicLinkName
);

typedef _IRQL_requires_max_(APC_LEVEL)
_Kernel_clear_do_init_(__yes)
VOID (*PFN_IoDeleteDevice)(
    _In_ __drv_freesMem(Mem) PDEVICE_OBJECT DeviceObject
);

VOID PsImageHandler(
    _In_ PUNICODE_STRING    FullImageName,
    _In_ HANDLE             ProcessId,
    _In_ PIMAGE_INFO        ImageInfo
);

VOID DriverUnload(
    _In_ PDRIVER_OBJECT     DriverObject
);

#define MAX_CONFIGURATION_DATA_SIZE 1024

typedef struct _MAPPED_CODE_DATA {
    // Lock
    ULONG   fInititialized;
    LONG    iNotifyCounter;

    // API pointers
    PFN_wcsnicmp                        _wcsnicmp;
    PFN_IoAllocateMdl                   IoAllocateMdl;
    PFN_IofCompleteRequest              IofCompleteRequest;
    PFN_IoFreeMdl                       IoFreeMdl;
    PFN_IoDeleteDevice                  IoDeleteDevice;
    PFN_IoDeleteSymbolicLink            IoDeleteSymbolicLink;
    PFN_KeDelayExecutionThread          KeDelayExecutionThread;
    PFN_PsGetCurrentProcessId           PsGetCurrentProcessId;
    PFN_PsSetLoadImageNotifyRoutine     PsSetLoadImageNotifyRoutine;
    PFN_PsRemoveLoadImageNotifyRoutine  PsRemoveLoadImageNotifyRoutine;
    PFN_MmProtectMdlSystemAddress       MmProtectMdlSystemAddress;
    PFN_MmUnmapLockedPages              MmUnmapLockedPages;
    PFN_MmUnlockPages                   MmUnlockPages;
    PFN_MmProbeAndLockPages             MmProbeAndLockPages;
    PFN_MmMapLockedPagesSpecifyCache    MmMapLockedPagesSpecifyCache;
    PFN_RtlInitUnicodeString            RtlInitUnicodeString;

    // data
    ULONG   ConfigurationDataSize;
    UCHAR   ConfigurationData[MAX_CONFIGURATION_DATA_SIZE];
} MAPPED_CODE_DATA, * PMAPPED_CODE_DATA;

#endif /* _TSUGUMI_H_ */