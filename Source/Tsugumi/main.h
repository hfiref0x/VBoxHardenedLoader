/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016
*
*  TITLE:       MAIN.H
*
*  VERSION:     1.60
*
*  DATE:        30 Apr 2016
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

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
NTSTATUS            TsmiHandleMemWrite(_In_ PVOID SrcAddress, _In_ PVOID DestAddress, _In_ ULONG Size);
VOID                TsmiPsImageHandler(_In_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo);
NTSTATUS            TsmiLoadParameters(VOID);

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(INIT, TsmiLoadParameters)
#pragma alloc_text(PAGE, TsmiHandleMemWrite)
#pragma alloc_text(PAGE, TsmiPsImageHandler)

#define TSUGUMI_IOCTL_REFRESH_LIST    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0700, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef struct _BINARY_PATCH_BLOCK {
	ULONG	VirtualOffset;
	UCHAR	DataLength;
	UCHAR	Data[1];
} BINARY_PATCH_BLOCK, *PBINARY_PATCH_BLOCK;

#define TSUGUMI_TAG             'imsT'
#define BLOCK_DATA_OFFSET       (ULONG_PTR)(&((PBINARY_PATCH_BLOCK)0)->Data)
#define TSUGUMI_DRV_OBJECT      L"\\Driver\\TsmiDrv"
#define TSUGUMI_DEV_OBJECT      L"\\Device\\Tsugumi"
#define TSUGUMI_SYM_LINK        L"\\DosDevices\\Tsugumi"
#define TSUGUMI_PARAMS          L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tsugumi\\Parameters"
