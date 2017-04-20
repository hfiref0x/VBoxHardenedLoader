/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2017
*
*  TITLE:       MAIN.H
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

#pragma once

typedef struct _VBOX_PATCH {
    KMUTEX Lock; // Synchronization mutex
    PKEY_VALUE_PARTIAL_INFORMATION Chains; // bufer
    ULONG_PTR ChainsLength; // buffer length in bytes
} VBOX_PATCH, *PVBOX_PATCH;

typedef struct _BINARY_PATCH_BLOCK {
    ULONG	VirtualOffset;
    UCHAR	DataLength;
    UCHAR	Data[1];
} BINARY_PATCH_BLOCK, *PBINARY_PATCH_BLOCK;

NTKERNELAPI
NTSTATUS
IoCreateDriver(
    IN PUNICODE_STRING DriverName, OPTIONAL
    IN PDRIVER_INITIALIZE InitializationFunction
);

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH DevioctlDispatch;
_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH CreateCloseDispatch;

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CREATE_NAMED_PIPE)
_Dispatch_type_(IRP_MJ_CLOSE)
_Dispatch_type_(IRP_MJ_READ)
_Dispatch_type_(IRP_MJ_WRITE)
_Dispatch_type_(IRP_MJ_QUERY_INFORMATION)
_Dispatch_type_(IRP_MJ_SET_INFORMATION)
_Dispatch_type_(IRP_MJ_QUERY_EA)
_Dispatch_type_(IRP_MJ_SET_EA)
_Dispatch_type_(IRP_MJ_FLUSH_BUFFERS)
_Dispatch_type_(IRP_MJ_QUERY_VOLUME_INFORMATION)
_Dispatch_type_(IRP_MJ_SET_VOLUME_INFORMATION)
_Dispatch_type_(IRP_MJ_DIRECTORY_CONTROL)
_Dispatch_type_(IRP_MJ_FILE_SYSTEM_CONTROL)
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
_Dispatch_type_(IRP_MJ_INTERNAL_DEVICE_CONTROL)
_Dispatch_type_(IRP_MJ_SHUTDOWN)
_Dispatch_type_(IRP_MJ_LOCK_CONTROL)
_Dispatch_type_(IRP_MJ_CLEANUP)
_Dispatch_type_(IRP_MJ_CREATE_MAILSLOT)
_Dispatch_type_(IRP_MJ_QUERY_SECURITY)
_Dispatch_type_(IRP_MJ_SET_SECURITY)
_Dispatch_type_(IRP_MJ_POWER)
_Dispatch_type_(IRP_MJ_SYSTEM_CONTROL)
_Dispatch_type_(IRP_MJ_DEVICE_CHANGE)
_Dispatch_type_(IRP_MJ_QUERY_QUOTA)
_Dispatch_type_(IRP_MJ_SET_QUOTA)
_Dispatch_type_(IRP_MJ_PNP)
DRIVER_DISPATCH UnsupportedDispatch;

DRIVER_INITIALIZE   DriverEntry;
DRIVER_INITIALIZE   DriverInitialize;
DRIVER_UNLOAD       DriverUnload;
NTSTATUS            TsmiHandleMemWrite(_In_ PVOID SrcAddress, _In_ PVOID DestAddress, _In_ ULONG Size);
NTSTATUS            TsmiLoadParameters(VOID);
NTSTATUS            TsmiPatchImage(_In_ VBOX_PATCH *PatchInfo, _In_ PIMAGE_INFO ImageInfo);
NTSTATUS            TsmiReadPatchChains(_In_ HANDLE sKey, _In_ PUNICODE_STRING ParamName, _In_ VBOX_PATCH *PatchInfo);
VOID                TsmiPsImageHandler(_In_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo);
VOID                TsmiListPatchChains(_In_ KEY_VALUE_PARTIAL_INFORMATION *PatchChains);
VOID                TsmiCopyPatchChainsData(_In_ VBOX_PATCH *Src, _In_ VBOX_PATCH *Dst);

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(INIT, DriverInitialize)
#pragma alloc_text(PAGE, TsmiLoadParameters)
#pragma alloc_text(PAGE, TsmiHandleMemWrite)
#pragma alloc_text(PAGE, TsmiPsImageHandler)
#pragma alloc_text(PAGE, TsmiPatchImage)
#pragma alloc_text(PAGE, TsmiCopyPatchChainsData)
#pragma alloc_text(PAGE, TsmiListPatchChains)
#pragma alloc_text(PAGE, TsmiReadPatchChains)
#pragma alloc_text(PAGE, DevioctlDispatch)
#pragma alloc_text(PAGE, CreateCloseDispatch)
#pragma alloc_text(PAGE, UnsupportedDispatch)
#pragma alloc_text(PAGE, DriverUnload)

#define TSUGUMI_IOCTL_REFRESH_LIST    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0700, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define TSUGUMI_IOCTL_MONITOR_STOP    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0701, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define TSUGUMI_TAG             'imsT'
#define BLOCK_DATA_OFFSET       (ULONG_PTR)(&((PBINARY_PATCH_BLOCK)0)->Data)
#define TSUGUMI_DRV_OBJECT      L"\\Driver\\TsmiDrv"
#define TSUGUMI_DEV_OBJECT      L"\\Device\\Tsugumi"
#define TSUGUMI_SYM_LINK        L"\\DosDevices\\Tsugumi"
#define TSUGUMI_PARAMS          L"\\REGISTRY\\MACHINE\\SOFTWARE\\Tsugumi\\Parameters"

#pragma warning(disable: 6320) // exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER
