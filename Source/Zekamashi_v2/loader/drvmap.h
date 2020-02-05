/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020
*
*  TITLE:       DRVMAP.H
*
*  VERSION:     1.00
*
*  DATE:        24 Jan 2020
*
*  Prototypes and definitions for driver mapping.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define MAX_CONFIGURATION_DATA_SIZE 1024

typedef struct _MAPPED_CODE_DATA {
    // Lock
    ULONG   fInititialized;
    LONG    iNotifyCounter;

    // API pointers
    PVOID   _wcsnicmp;
    PVOID   IoAllocateMdl;
    PVOID   IofCompleteRequest;
    PVOID   IoFreeMdl;
    PVOID   IoDeleteDevice;
    PVOID   IoDeleteSymbolicLink;
    PVOID   KeDelayExecutionThread;
    PVOID   PsGetCurrentProcessId;
    PVOID   PsSetLoadImageNotifyRoutine;
    PVOID   PsRemoveLoadImageNotifyRoutine;
    PVOID   MmProtectMdlSystemAddress;
    PVOID   MmUnmapLockedPages;
    PVOID   MmUnlockPages;
    PVOID   MmProbeAndLockPages;
    PVOID   MmMapLockedPagesSpecifyCache;
    PVOID   RtlInitUnicodeString;

    // data
    ULONG   ConfigurationDataSize;
    UCHAR   ConfigurationData[MAX_CONFIGURATION_DATA_SIZE];
} MAPPED_CODE_DATA, * PMAPPED_CODE_DATA;

BOOL MapTsugumi(
    _In_ PTABLE_DESC ConfigurationData);
