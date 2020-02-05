/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2020
*
*  TITLE:       PATTERNS.C
*
*  VERSION:     2.00
*
*  DATE:        24 Jan 2020
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

#define MAX_HWID_BLOCKS_DEEP   32
#define MAX_PATCH_BLOCKS       64

BINARY_PATCH_BLOCK_INTERNAL* DataBlocks;

/*
* BuildTable
*
* Purpose:
*
* Build table to memory buffer. Use RtlFreeHeap when this buffer is no longer needed.
*
*/
BOOL BuildTable(
    _In_        BINARY_PATCH_BLOCK_INTERNAL* PatchBlock,
    _In_        UINT BlockCount,
    _In_        PVOID* OutputBuffer,
    _Inout_opt_ DWORD* OutputBufferSize
)
{
    UINT    i;
    BOOL    bResult = FALSE;
    PUCHAR  Table = NULL;
    SIZE_T  TableSize = 0;
    DWORD   ProcessedSize, dwEntrySize;

    if (OutputBuffer == NULL)
        return FALSE;

    TableSize = BlockCount * sizeof(BINARY_PATCH_BLOCK_INTERNAL);
    Table = (PUCHAR)supHeapAlloc(TableSize);
    if (Table) {
        ProcessedSize = 0;
        for (i = 0; i < BlockCount; i++) {
            dwEntrySize = sizeof(ULONG) + sizeof(UCHAR) + (sizeof(UCHAR) * PatchBlock[i].DataLength);
            if (ProcessedSize + dwEntrySize > (DWORD)TableSize)
                break;
            RtlCopyMemory(&Table[ProcessedSize], &PatchBlock[i], dwEntrySize);
            ProcessedSize += dwEntrySize;
        }
        //error converting table, entries are missing
        if (i != BlockCount) {
            supHeapFree(Table);
            return FALSE;
        }

        *OutputBuffer = Table;

        if (OutputBufferSize) {
            *OutputBufferSize = ProcessedSize;
        }

        bResult = TRUE;
    }
    return bResult;
}

#define PATTERN_FOUND(s, x) { printf_s("%s\t\t0x%lx\r\n", s, x);} 
#define PATTERN_FOUND2(s, x) { printf_s("%s\t0x%lx\r\n", s, x);} 

#define PATTERN_NOT_FOUND(s) { printf_s("Pattern %s was not found\r\n", s); }

/*
* ProcessVirtualBoxFile
*
* Purpose:
*
* Search for known patterns inside VirtualBox file and build resulting table.
*
*/
UINT ProcessVirtualBoxFile(
    _In_        LPTSTR lpszPath,
    _In_        PVOID* OutputBuffer,
    _Inout_opt_ DWORD* OutputBufferSize
)
{
    UINT                uResult = (UINT)-1;
    ULONG               c = 0, d = 0;

    HANDLE              fh = NULL, sec = NULL;
    OBJECT_ATTRIBUTES   attr;
    UNICODE_STRING      usFileName;
    IO_STATUS_BLOCK     iosb;
    NTSTATUS            status;
    PBYTE               DllBase = NULL, Pattern;
    SIZE_T              DllVirtualSize;

    RtlSecureZeroMemory(&usFileName, sizeof(usFileName));

    do {

        if (RtlDosPathNameToNtPathName_U(lpszPath, &usFileName, NULL, NULL) == FALSE)
            break;

        InitializeObjectAttributes(&attr, &usFileName,
            OBJ_CASE_INSENSITIVE, NULL, NULL);
        RtlSecureZeroMemory(&iosb, sizeof(iosb));

        status = NtCreateFile(&fh, SYNCHRONIZE | FILE_READ_DATA,
            &attr, &iosb, NULL, 0, FILE_SHARE_READ, FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

        if (!NT_SUCCESS(status))
            break;

        status = NtCreateSection(&sec, SECTION_ALL_ACCESS, NULL,
            NULL, PAGE_READONLY, SEC_IMAGE, fh);
        if (!NT_SUCCESS(status))
            break;

        DllBase = NULL;
        DllVirtualSize = 0;
        status = NtMapViewOfSection(sec, NtCurrentProcess(), &DllBase,
            0, 0, NULL, &DllVirtualSize, ViewUnmap, 0, PAGE_READONLY);
        if (!NT_SUCCESS(status))
            break;

        DataBlocks = (BINARY_PATCH_BLOCK_INTERNAL*)supHeapAlloc(sizeof(BINARY_PATCH_BLOCK_INTERNAL) * MAX_PATCH_BLOCKS);
        if (DataBlocks == NULL)
            break;

        c = 0;

        //locate VBOX patterns
        printf_s("\r\n%s\r\n\r\n", "Pattern matching: 'VBOX'");

        //
        // FACP
        //
        Pattern = supFindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)FACP_PATTERN, sizeof(FACP_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(4 + Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(VBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, VBOX_PATCH, DataBlocks[c].DataLength);
            PATTERN_FOUND("FACP (pre v6.1)", (ULONG)DataBlocks[c].VirtualOffset);
            c += 1;
        }
        else {
            PATTERN_NOT_FOUND("FACP (pre v6.1)");
        }

        Pattern = supFindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)FACP_PATTERN_61, sizeof(FACP_PATTERN_61));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(4 + Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(VBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, VBOX_PATCH, DataBlocks[c].DataLength);
            PATTERN_FOUND("FACP (v6.1+)", (ULONG)DataBlocks[c].VirtualOffset);
            c += 1;
        }
        else {
            PATTERN_NOT_FOUND("FACP (v6.1+)");
        }

        //
        // RSDT
        //
        Pattern = supFindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)RSDT_PATTERN, sizeof(RSDT_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(3 + Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(VBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, VBOX_PATCH, DataBlocks[c].DataLength);
            PATTERN_FOUND("RSDT (pre 6.1)", (ULONG)DataBlocks[c].VirtualOffset);
            c += 1;
        }
        else {
            PATTERN_NOT_FOUND("RSDT (pre 6.1)");
        }

        Pattern = supFindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)RSDT_PATTERN_61, sizeof(RSDT_PATTERN_61));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(3 + Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(VBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, VBOX_PATCH, DataBlocks[c].DataLength);
            PATTERN_FOUND("RSDT (6.1+)", (ULONG)DataBlocks[c].VirtualOffset);
            c += 1;
        }
        else {
            PATTERN_NOT_FOUND("RSDT (pre 6.1+)");
        }

        //
        // XSDT
        //
        Pattern = supFindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)XSDT_PATTERN, sizeof(XSDT_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(3 + Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(VBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, VBOX_PATCH, DataBlocks[c].DataLength);
            PATTERN_FOUND("XSDT", (ULONG)DataBlocks[c].VirtualOffset);
            c += 1;
        }
        else {
            PATTERN_NOT_FOUND("XSDT");
        }

        //
        // APIC
        //
        Pattern = supFindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)APIC_PATTERN, sizeof(APIC_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(3 + Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(VBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, VBOX_PATCH, DataBlocks[c].DataLength);
            PATTERN_FOUND("APIC", (ULONG)DataBlocks[c].VirtualOffset);
            c += 1;
        }
        else {
            PATTERN_NOT_FOUND("APIC");
        }

        //
        // HPET
        //
        Pattern = supFindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)HPET_PATTERN, sizeof(HPET_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(3 + Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(VBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, VBOX_PATCH, DataBlocks[c].DataLength);
            PATTERN_FOUND("HPET", (ULONG)DataBlocks[c].VirtualOffset);
            c += 1;
        }
        else {
            PATTERN_NOT_FOUND("HPET");
        }

        //
        // MCFG
        //
        Pattern = supFindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)MCFG_PATTERN, sizeof(MCFG_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(3 + Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(VBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, VBOX_PATCH, DataBlocks[c].DataLength);
            PATTERN_FOUND("MCFG", (ULONG)DataBlocks[c].VirtualOffset);
            c += 1;
        }
        else {
            PATTERN_NOT_FOUND("MCFG");
        }

        //
        // VBOXCPU
        //
        Pattern = supFindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)VBOXCPU_PATTERN, sizeof(VBOXCPU_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(2 + Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(VBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, VBOX_PATCH, DataBlocks[c].DataLength);
            PATTERN_FOUND("VBOXCPU", (ULONG)DataBlocks[c].VirtualOffset);
            c += 1;
        }
        else {
            PATTERN_NOT_FOUND("VBOXCPU");
        }

        //
        // VBOX 1.0 CDROM
        //
        /*
        Pattern = supFindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)CDROMVBOX_PATTERN, sizeof(CDROMVBOX_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(12 + Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(VBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, VBOX_PATCH, DataBlocks[c].DataLength);
            PATTERN_FOUND("VBOXCDOM", (ULONG)DataBlocks[c].VirtualOffset);
            c += 1;
        }
        else {
            PATTERN_NOT_FOUND("VBOXCDROM");
        }
        */

        //
        // VBOX generic
        //
        Pattern = supFindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)JUSTVBOX_PATTERN, sizeof(JUSTVBOX_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(3 + Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(VBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, VBOX_PATCH, DataBlocks[c].DataLength);
            PATTERN_FOUND("VBOX (pre 6.1)", (ULONG)DataBlocks[c].VirtualOffset);
            c += 1;
        }
        else {
            PATTERN_NOT_FOUND("VBOX generic (pre 6.1)");
        }

        Pattern = supFindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)JUSTVBOX_PATTERN_61, sizeof(JUSTVBOX_PATTERN_61));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(3 + Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(VBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, VBOX_PATCH, DataBlocks[c].DataLength);
            PATTERN_FOUND("VBOX (6.1+)", (ULONG)DataBlocks[c].VirtualOffset);
            c += 1;
        }
        else {
            PATTERN_NOT_FOUND("VBOX generic (6.1+)");
        }

        //locate VirtualBox pattern
        printf_s("\r\n%s\r\n\r\n", "Pattern matching: 'VirtualBox'");

        //
        // 'VirtualBox'
        //
        Pattern = supFindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)JUSTVIRTUALBOX_PATTERN, sizeof(JUSTVIRTUALBOX_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(JUSTVIRTUALBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, JUSTVIRTUALBOX_PATCH, DataBlocks[c].DataLength);
            PATTERN_FOUND2("VirtualBox", (ULONG)DataBlocks[c].VirtualOffset);
            c += 1;
        }
        else {
            PATTERN_NOT_FOUND("VirtualBox");
        }

        //
        // 'VirtualBox__'
        //
        Pattern = supFindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)VIRTUALBOX2020_PATTERN, sizeof(VIRTUALBOX2020_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(JUSTVIRTUALBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, JUSTVIRTUALBOX_PATCH, DataBlocks[c].DataLength);
            PATTERN_FOUND2("VirtualBox__", (ULONG)DataBlocks[c].VirtualOffset);
            c += 1;
        }
        else {
            PATTERN_NOT_FOUND("VirtualBox__");
        }

        //
        // 'VirtualBox GIM'
        //
        Pattern = supFindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)VIRTUALBOXGIM_PATTERN, sizeof(VIRTUALBOXGIM_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(JUSTVIRTUALBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, JUSTVIRTUALBOX_PATCH, DataBlocks[c].DataLength);
            PATTERN_FOUND2("VirtualBox GIM", (ULONG)DataBlocks[c].VirtualOffset);
            c += 1;
        }
        else {
            PATTERN_NOT_FOUND("VirtualBox GIM");
        }

        //
        // 'VirtualBox VMM'
        //
        Pattern = supFindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)VIRTUALBOXVMM_PATTERN, sizeof(VIRTUALBOXVMM_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(JUSTVIRTUALBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, JUSTVIRTUALBOX_PATCH, DataBlocks[c].DataLength);
            PATTERN_FOUND2("VirtualBox VMM", (ULONG)DataBlocks[c].VirtualOffset);
            c += 1;
        }
        else {
            PATTERN_NOT_FOUND("VirtualBox VMM");
        }

        //locate Configuration pattern
        printf_s("\r\n%s\r\n\r\n", "Pattern matching: 'Configuration'");

        Pattern = supFindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)CFGSTRINGS_PATTERN, sizeof(CFGSTRINGS_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(26 + Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(CONFIGURATION_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, CONFIGURATION_PATCH, DataBlocks[c].DataLength);
            PATTERN_FOUND("Configuration (pre 6.1)", (ULONG)DataBlocks[c].VirtualOffset);
            c += 1;
        }
        else {
            PATTERN_NOT_FOUND("Configuration (pre 6.1)");
        }

        Pattern = supFindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)CFGSTRINGS_PATTERN_61, sizeof(CFGSTRINGS_PATTERN_61));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(26 + Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(CONFIGURATION_PATCH_61);
            RtlCopyMemory(DataBlocks[c].Data, CONFIGURATION_PATCH_61, DataBlocks[c].DataLength);
            PATTERN_FOUND("Configuration (6.1+)", (ULONG)DataBlocks[c].VirtualOffset);
            c += 1;
        }
        else {
            PATTERN_NOT_FOUND("Configuration (6.1+)");
        }


        //
        // HWID
        //
        printf_s("\r\n%s\r\n\r\n", "Pattern matching: Hardware ID");

        //
        // 80EE
        //
        d = 0;
        Pattern = DllBase;
        do {
            Pattern = supFindPattern(
                (CONST PBYTE)Pattern, DllVirtualSize - (Pattern - DllBase),
                (CONST PBYTE)PCI80EE_PATTERN, sizeof(PCI80EE_PATTERN));
            if (Pattern) {
                DataBlocks[c].VirtualOffset = (ULONG)(1 + Pattern - DllBase);
                DataBlocks[c].DataLength = sizeof(HWID_PATCH_VIDEO_1);
                RtlCopyMemory(DataBlocks[c].Data, HWID_PATCH_VIDEO_1, DataBlocks[c].DataLength);
                PATTERN_FOUND("80EE", (ULONG)DataBlocks[c].VirtualOffset);
                c += 1;
                d += 1;
                if (d > MAX_HWID_BLOCKS_DEEP) {
                    printf_s("\r\nLDR: Maximum hwid blocks deep, abort scan.\r\n");
                    break;
                }
            }
            else {
                break;
            }
            Pattern++;
        } while (DllVirtualSize - (Pattern - DllBase) > 0);

        //
        // BEEF
        //

        d = 0;
        Pattern = DllBase;
        do {
            Pattern = supFindPattern(
                (CONST PBYTE)Pattern, DllVirtualSize - (Pattern - DllBase),
                (CONST PBYTE)PCIBEEF_PATTERN, sizeof(PCIBEEF_PATTERN));
            if (Pattern) {
                DataBlocks[c].VirtualOffset = (ULONG)(1 + Pattern - DllBase);
                DataBlocks[c].DataLength = sizeof(HWID_PATCH_VIDEO_2);
                RtlCopyMemory(DataBlocks[c].Data, HWID_PATCH_VIDEO_2, DataBlocks[c].DataLength);
                PATTERN_FOUND("BEEF", (ULONG)DataBlocks[c].VirtualOffset);
                c += 1;
                d += 1;
                if (d > MAX_HWID_BLOCKS_DEEP) {
                    printf_s("\r\nLDR: Maximum hwid blocks deep, abort scan.\r\n");
                    break;
                }
            }
            else {
                break;
            }
            Pattern++;
        } while (DllVirtualSize - (Pattern - DllBase) > 0);

        //
        // CAFE
        //
        Pattern = supFindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)PCICAFE_PATTERN, sizeof(PCICAFE_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(1 + Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(HWID_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, HWID_PATCH, DataBlocks[c].DataLength);
            PATTERN_FOUND("CAFE", (ULONG)DataBlocks[c].VirtualOffset);
            c += 1;
        }
        else {
            PATTERN_NOT_FOUND("CAFE");
        }

        if (BuildTable(DataBlocks, c, OutputBuffer, OutputBufferSize))
            uResult = 0;
        else
            uResult = (UINT)-2;

    } while (FALSE);

    if (usFileName.Buffer != NULL) {
        RtlFreeUnicodeString(&usFileName);
    }

    if (DllBase != NULL)
        NtUnmapViewOfSection(NtCurrentProcess(), DllBase);

    if (sec != NULL)
        NtClose(sec);

    if (fh != NULL)
        NtClose(fh);

    if (DataBlocks != NULL)
        RtlFreeHeap(GetProcessHeap(), 0, DataBlocks);

    return uResult;
}


