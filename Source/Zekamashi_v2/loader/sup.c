/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2020
*
*  TITLE:       SUP.C
*
*  VERSION:     2.02
*
*  DATE:        19 June 2020
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

#define ENABLE_ERROR_LOGGING 1

#ifdef ENABLE_ERROR_LOGGING
#define printError(...) printf(__VA_ARGS__)
#else
#define printError(...) 
#endif

/*
* supHeapAlloc
*
* Purpose:
*
* Wrapper for RtlAllocateHeap with WinObjEx heap.
*
*/
PVOID supHeapAlloc(
    _In_ SIZE_T Size)
{
    return RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Size);
}

/*
* supHeapFree
*
* Purpose:
*
* Wrapper for RtlFreeHeap with WinObjEx heap.
*
*/
BOOL supHeapFree(
    _In_ PVOID Memory)
{
    return RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Memory);
}

/*
* supPurgeSystemCache
*
* Purpose:
*
* Flush file cache and memory standby list.
*
*/
VOID supPurgeSystemCache(
    VOID
)
{
    SYSTEM_FILECACHE_INFORMATION sfc;
    SYSTEM_MEMORY_LIST_COMMAND smlc;

    //flush file system cache
    if (NT_SUCCESS(supEnablePrivilege(SE_INCREASE_QUOTA_PRIVILEGE, TRUE))) {
        RtlSecureZeroMemory(&sfc, sizeof(SYSTEM_FILECACHE_INFORMATION));
        sfc.MaximumWorkingSet = (SIZE_T)-1;
        sfc.MinimumWorkingSet = (SIZE_T)-1;
        NtSetSystemInformation(SystemFileCacheInformation, &sfc, sizeof(sfc));
    }

    //flush standby list
    if (NT_SUCCESS(supEnablePrivilege(SE_PROF_SINGLE_PROCESS_PRIVILEGE, TRUE))) {
        smlc = MemoryPurgeStandbyList;
        NtSetSystemInformation(SystemMemoryListInformation, &smlc, sizeof(smlc));
    }
}

/*
* supxDeleteKeyRecursive
*
* Purpose:
*
* Delete key and all it subkeys/values.
*
*/
BOOL supxDeleteKeyRecursive(
    _In_ HKEY hKeyRoot,
    _In_ LPWSTR lpSubKey)
{
    LPWSTR lpEnd;
    LONG lResult;
    DWORD dwSize;
    WCHAR szName[MAX_PATH + 1];
    HKEY hKey;
    FILETIME ftWrite;

    //
    // Attempt to delete key as is.
    //
    lResult = RegDeleteKey(hKeyRoot, lpSubKey);
    if (lResult == ERROR_SUCCESS)
        return TRUE;

    //
    // Try to open key to check if it exist.
    //
    lResult = RegOpenKeyEx(hKeyRoot, lpSubKey, 0, KEY_READ, &hKey);
    if (lResult != ERROR_SUCCESS) {
        if (lResult == ERROR_FILE_NOT_FOUND)
            return TRUE;
        else
            return FALSE;
    }

    //
    // Add slash to the key path if not present.
    //
    lpEnd = _strend(lpSubKey);
    if (*(lpEnd - 1) != TEXT('\\')) {
        *lpEnd = TEXT('\\');
        lpEnd++;
        *lpEnd = TEXT('\0');
    }

    //
    // Enumerate subkeys and call this func for each.
    //
    dwSize = MAX_PATH;
    lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
        NULL, NULL, &ftWrite);

    if (lResult == ERROR_SUCCESS) {

        do {

            _strncpy(lpEnd, MAX_PATH, szName, MAX_PATH);

            if (!supxDeleteKeyRecursive(hKeyRoot, lpSubKey))
                break;

            dwSize = MAX_PATH;

            lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
                NULL, NULL, &ftWrite);

        } while (lResult == ERROR_SUCCESS);
    }

    lpEnd--;
    *lpEnd = TEXT('\0');

    RegCloseKey(hKey);

    //
    // Delete current key, all it subkeys should be already removed.
    //
    lResult = RegDeleteKey(hKeyRoot, lpSubKey);
    if (lResult == ERROR_SUCCESS)
        return TRUE;

    return FALSE;
}

/*
* supRegDeleteKeyRecursive
*
* Purpose:
*
* Delete key and all it subkeys/values.
*
* Remark:
*
* SubKey should not be longer than 260 chars.
*
*/
BOOL supRegDeleteKeyRecursive(
    _In_ HKEY hKeyRoot,
    _In_ LPWSTR lpSubKey)
{
    WCHAR szKeyName[MAX_PATH * 2];
    RtlSecureZeroMemory(szKeyName, sizeof(szKeyName));
    _strncpy(szKeyName, MAX_PATH * 2, lpSubKey, MAX_PATH);
    return supxDeleteKeyRecursive(hKeyRoot, szKeyName);
}

/*
* supEnablePrivilege
*
* Purpose:
*
* Enable/Disable given privilege.
*
* Return NTSTATUS value.
*
*/
NTSTATUS supEnablePrivilege(
    _In_ DWORD Privilege,
    _In_ BOOL Enable
)
{
    ULONG Length;
    NTSTATUS Status;
    HANDLE TokenHandle;
    LUID LuidPrivilege;

    PTOKEN_PRIVILEGES NewState;
    UCHAR Buffer[sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES)];

    Status = NtOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &TokenHandle);

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    NewState = (PTOKEN_PRIVILEGES)Buffer;

    LuidPrivilege = RtlConvertUlongToLuid(Privilege);

    NewState->PrivilegeCount = 1;
    NewState->Privileges[0].Luid = LuidPrivilege;
    NewState->Privileges[0].Attributes = Enable ? SE_PRIVILEGE_ENABLED : 0;

    Status = NtAdjustPrivilegesToken(TokenHandle,
        FALSE,
        NewState,
        sizeof(Buffer),
        NULL,
        &Length);

    if (Status == STATUS_NOT_ALL_ASSIGNED) {
        Status = STATUS_PRIVILEGE_NOT_HELD;
    }

    NtClose(TokenHandle);
    return Status;
}

/*
* supCopyMemory
*
* Purpose:
*
* Copies bytes between buffers.
*
* dest - Destination buffer
* cbdest - Destination buffer size in bytes
* src - Source buffer
* cbsrc - Source buffer size in bytes
*
*/
void supCopyMemory(
    _Inout_ void* dest,
    _In_ size_t cbdest,
    _In_ const void* src,
    _In_ size_t cbsrc
)
{
    char* d = (char*)dest;
    char* s = (char*)src;

    if ((dest == 0) || (src == 0) || (cbdest == 0))
        return;
    if (cbdest < cbsrc)
        cbsrc = cbdest;

    while (cbsrc > 0) {
        *d++ = *s++;
        cbsrc--;
    }
}

/*
* supGetSystemInfo
*
* Purpose:
*
* Wrapper for NtQuerySystemInformation.
*
*/
PVOID supGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS InfoClass
)
{
    INT         c = 0;
    PVOID       Buffer = NULL;
    ULONG		Size = 0x1000;
    NTSTATUS    status;
    ULONG       memIO;

    do {
        Buffer = supHeapAlloc((SIZE_T)Size);
        if (Buffer != NULL) {
            status = NtQuerySystemInformation(InfoClass, Buffer, Size, &memIO);
        }
        else {
            return NULL;
        }
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            supHeapFree(Buffer);
            Buffer = NULL;
            Size *= 2;
            c++;
            if (c > 100) {
                status = STATUS_SECRET_TOO_LONG;
                break;
            }
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (NT_SUCCESS(status)) {
        return Buffer;
    }

    if (Buffer) {
        supHeapFree(Buffer);
    }
    return NULL;
}

/*
* supProcessExist
*
* Purpose:
*
* Return TRUE if specified process launched, FALSE otherwise or on error.
*
*/
BOOL supProcessExist(
    _In_ LPWSTR lpProcessName
)
{
    PSYSTEM_PROCESSES_INFORMATION ProcessList, pList;
    UNICODE_STRING procName;
    BOOL bResult = FALSE;

    ProcessList = (PSYSTEM_PROCESSES_INFORMATION)supGetSystemInfo(SystemProcessInformation);
    if (ProcessList == NULL) {
        return bResult;
    }

    do {
        RtlSecureZeroMemory(&procName, sizeof(procName));
        RtlInitUnicodeString(&procName, lpProcessName);
        pList = ProcessList;

        for (;;) {
            if (RtlEqualUnicodeString(&procName, &pList->ImageName, TRUE)) {
                bResult = TRUE;
                break;
            }
            if (pList->NextEntryDelta == 0) {
                break;
            }
            pList = (PSYSTEM_PROCESSES_INFORMATION)(((LPBYTE)pList) + pList->NextEntryDelta);
        }

    } while (FALSE);

    supHeapFree(ProcessList);
    return bResult;
}

/*
* supxCreateDriverEntry
*
* Purpose:
*
* Creating registry entry for driver.
*
*/
NTSTATUS supxCreateDriverEntry(
    _In_opt_ LPCWSTR DriverPath,
    _In_ LPCWSTR KeyName
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD dwData, dwResult;
    HKEY keyHandle = NULL;
    UNICODE_STRING driverImagePath;

    RtlInitEmptyUnicodeString(&driverImagePath, NULL, 0);

    if (DriverPath) {
        if (!RtlDosPathNameToNtPathName_U(DriverPath,
            &driverImagePath,
            NULL,
            NULL))
        {
            printError("[!] %s, RtlDosPathNameToNtPathName_U failed\r\n", __FUNCTION__);
            return STATUS_INVALID_PARAMETER_2;
        }
    }

    if (ERROR_SUCCESS != RegCreateKeyEx(HKEY_LOCAL_MACHINE,
        KeyName,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS,
        NULL,
        &keyHandle,
        NULL))
    {
        status = STATUS_ACCESS_DENIED;
        printError("[!] %s, RegCreateKeyEx failed with error %lu\r\n", __FUNCTION__, GetLastError());
        goto Cleanup;
    }

    dwResult = ERROR_SUCCESS;

    do {

        dwData = SERVICE_ERROR_NORMAL;
        dwResult = RegSetValueEx(keyHandle,
            TEXT("ErrorControl"),
            0,
            REG_DWORD,
            (BYTE*)&dwData,
            sizeof(dwData));
        if (dwResult != ERROR_SUCCESS) {
            printError("[!] %s, RegSetValueEx(ErrorControl) failed with error %lu\r\n", __FUNCTION__, GetLastError());
            break;
        }

        dwData = SERVICE_KERNEL_DRIVER;
        dwResult = RegSetValueEx(keyHandle,
            TEXT("Type"),
            0,
            REG_DWORD,
            (BYTE*)&dwData,
            sizeof(dwData));
        if (dwResult != ERROR_SUCCESS) {
            printError("[!] %s, RegSetValueEx(Type) failed with error %lu\r\n", __FUNCTION__, GetLastError());
            break;
        }

        dwData = SERVICE_DEMAND_START;
        dwResult = RegSetValueEx(keyHandle,
            TEXT("Start"),
            0,
            REG_DWORD,
            (BYTE*)&dwData,
            sizeof(dwData));

        if (dwResult != ERROR_SUCCESS) {
            printError("[!] %s, RegSetValueEx(Start) failed with error %lu\r\n", __FUNCTION__, GetLastError());
            break;
        }

        if (DriverPath) {
            dwResult = RegSetValueEx(keyHandle,
                TEXT("ImagePath"),
                0,
                REG_EXPAND_SZ,
                (BYTE*)driverImagePath.Buffer,
                (DWORD)driverImagePath.Length + sizeof(UNICODE_NULL));
            if (dwResult != ERROR_SUCCESS) {
                printError("[!] %s, RegSetValueEx(ImagePath) failed with error %lu\r\n", __FUNCTION__, GetLastError());
            }
        }

    } while (FALSE);

    RegCloseKey(keyHandle);

    if (dwResult != ERROR_SUCCESS) {
        printError("[!] %s, dwError %lu\r\n", __FUNCTION__, dwResult);
        status = STATUS_ACCESS_DENIED;
    }
    else
    {
        status = STATUS_SUCCESS;
    }

Cleanup:
    if (DriverPath) {
        if (driverImagePath.Buffer) {
            RtlFreeUnicodeString(&driverImagePath);
        }
    }
    return status;
}

/*
* supLoadDriver
*
* Purpose:
*
* Install driver and load it.
*
* N.B.
* SE_LOAD_DRIVER_PRIVILEGE is required to be assigned and enabled.
*
*/
NTSTATUS supLoadDriver(
    _In_ LPCWSTR DriverName,
    _In_ LPCWSTR DriverPath,
    _In_ BOOLEAN UnloadPreviousInstance
)
{
    SIZE_T keyOffset;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING driverServiceName;

    WCHAR szBuffer[MAX_PATH + 1];

    if (DriverName == NULL)
        return STATUS_INVALID_PARAMETER_1;
    if (DriverPath == NULL)
        return STATUS_INVALID_PARAMETER_2;

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

    keyOffset = RTL_NUMBER_OF(NT_REG_PREP);

    if (FAILED(StringCchPrintf(szBuffer, MAX_PATH,
        DRIVER_REGKEY,
        NT_REG_PREP,
        DriverName)))
    {
        printError("[!] Error building driver registry key name\r\n");
        return STATUS_INVALID_PARAMETER_1;
    }

    status = supxCreateDriverEntry(DriverPath,
        &szBuffer[keyOffset]);

    if (!NT_SUCCESS(status)) {
        printError("[!] Error building driver registry entry, NTSTATUS (0x%lX)\r\n", status);
        return status;
    }

    RtlInitUnicodeString(&driverServiceName, szBuffer);
    status = NtLoadDriver(&driverServiceName);

    printf("LDR: NtLoadDriver, NTSTATUS (0x%lX)\r\n", status);

    if (UnloadPreviousInstance) {
        if ((status == STATUS_IMAGE_ALREADY_LOADED) ||
            (status == STATUS_OBJECT_NAME_COLLISION) ||
            (status == STATUS_OBJECT_NAME_EXISTS))
        {
            status = NtUnloadDriver(&driverServiceName);
            if (NT_SUCCESS(status)) {
                status = NtLoadDriver(&driverServiceName);
            }
        }
    }
    else {
        if (status == STATUS_OBJECT_NAME_EXISTS)
            status = STATUS_SUCCESS;
    }

    return status;
}

/*
* supUnloadDriver
*
* Purpose:
*
* Call driver unload and remove corresponding registry key.
*
* N.B.
* SE_LOAD_DRIVER_PRIVILEGE is required to be assigned and enabled.
*
*/
NTSTATUS supUnloadDriver(
    _In_ LPCWSTR DriverName,
    _In_ BOOLEAN fRemove
)
{
    NTSTATUS status;
    SIZE_T keyOffset;
    UNICODE_STRING driverServiceName;

    WCHAR szBuffer[MAX_PATH + 1];

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

    if (FAILED(StringCchPrintf(szBuffer, MAX_PATH,
        DRIVER_REGKEY,
        NT_REG_PREP,
        DriverName)))
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    keyOffset = RTL_NUMBER_OF(NT_REG_PREP);

    status = supxCreateDriverEntry(NULL,
        &szBuffer[keyOffset]);

    if (!NT_SUCCESS(status))
        return status;

    RtlInitUnicodeString(&driverServiceName, szBuffer);
    status = NtUnloadDriver(&driverServiceName);

    if (NT_SUCCESS(status)) {
        if (fRemove)
            supRegDeleteKeyRecursive(HKEY_LOCAL_MACHINE, &szBuffer[keyOffset]);
    }

    return status;
}

/*
* supOpenDriver
*
* Purpose:
*
* Open handle for helper driver.
*
*/
NTSTATUS supOpenDriver(
    _In_ LPCWSTR DriverName,
    _Out_ PHANDLE DeviceHandle
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    UNICODE_STRING usDeviceLink;
    OBJECT_ATTRIBUTES obja;
    IO_STATUS_BLOCK iost;

    TCHAR szDeviceLink[MAX_PATH + 1];

    // assume failure
    if (DeviceHandle)
        *DeviceHandle = NULL;
    else
        return STATUS_INVALID_PARAMETER_2;

    if (DriverName) {

        RtlSecureZeroMemory(szDeviceLink, sizeof(szDeviceLink));

        if (FAILED(StringCchPrintf(szDeviceLink,
            MAX_PATH,
            TEXT("\\DosDevices\\%wS"),
            DriverName)))
        {
            return STATUS_INVALID_PARAMETER_1;
        }

        RtlInitUnicodeString(&usDeviceLink, szDeviceLink);
        InitializeObjectAttributes(&obja, &usDeviceLink, OBJ_CASE_INSENSITIVE, NULL, NULL);

        status = NtCreateFile(DeviceHandle,
            GENERIC_READ | GENERIC_WRITE,
            &obja,
            &iost,
            NULL,
            0,
            0,
            FILE_OPEN,
            0,
            NULL,
            0);

    }
    else {
        status = STATUS_INVALID_PARAMETER_1;
    }

    return status;
}

/*
* supGetNtOsBase
*
* Purpose:
*
* Return ntoskrnl base address.
*
*/
ULONG_PTR supGetNtOsBase(
    VOID
)
{
    PRTL_PROCESS_MODULES   miSpace;
    ULONG_PTR              NtOsBase = 0;

    miSpace = (PRTL_PROCESS_MODULES)supGetSystemInfo(SystemModuleInformation);
    if (miSpace) {
        NtOsBase = (ULONG_PTR)miSpace->Modules[0].ImageBase;
        RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, miSpace);
    }
    return NtOsBase;
}

/*
* supQueryResourceData
*
* Purpose:
*
* Load resource by given id (win32 FindResource, SizeofResource, LockResource).
*
*/
PBYTE supQueryResourceData(
    _In_ ULONG_PTR ResourceId,
    _In_ PVOID DllHandle,
    _In_ PULONG DataSize
)
{
    NTSTATUS                    status;
    ULONG_PTR                   IdPath[3];
    IMAGE_RESOURCE_DATA_ENTRY* DataEntry;
    PBYTE                       Data = NULL;
    ULONG                       SizeOfData = 0;

    if (DllHandle != NULL) {

        IdPath[0] = (ULONG_PTR)RT_RCDATA; //type
        IdPath[1] = ResourceId;           //id
        IdPath[2] = 0;                    //lang

        status = LdrFindResource_U(DllHandle, (ULONG_PTR*)&IdPath, 3, &DataEntry);
        if (NT_SUCCESS(status)) {
            status = LdrAccessResource(DllHandle, DataEntry, (PVOID*)&Data, &SizeOfData);
            if (NT_SUCCESS(status)) {
                if (DataSize) {
                    *DataSize = SizeOfData;
                }
            }
        }
    }
    return Data;
}

/*
* supWriteBufferToFile
*
* Purpose:
*
* Create new file (or open existing) and write (append) buffer to it.
*
*/
SIZE_T supWriteBufferToFile(
    _In_ PWSTR lpFileName,
    _In_ PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ BOOL Flush,
    _In_ BOOL Append,
    _Out_opt_ NTSTATUS* Result
)
{
    NTSTATUS           Status = STATUS_UNSUCCESSFUL;
    DWORD              dwFlag;
    HANDLE             hFile = NULL;
    OBJECT_ATTRIBUTES  attr;
    UNICODE_STRING     NtFileName;
    IO_STATUS_BLOCK    IoStatus;
    LARGE_INTEGER      Position;
    ACCESS_MASK        DesiredAccess;
    PLARGE_INTEGER     pPosition = NULL;
    ULONG_PTR          nBlocks, BlockIndex;
    ULONG              BlockSize, RemainingSize;
    PBYTE              ptr = (PBYTE)Buffer;
    SIZE_T             BytesWritten = 0;

    if (Result)
        *Result = STATUS_UNSUCCESSFUL;

    if (RtlDosPathNameToNtPathName_U(lpFileName, &NtFileName, NULL, NULL) == FALSE) {
        if (Result)
            *Result = STATUS_INVALID_PARAMETER_1;
        return 0;
    }

    DesiredAccess = FILE_WRITE_ACCESS | SYNCHRONIZE;
    dwFlag = FILE_OVERWRITE_IF;

    if (Append != FALSE) {
        DesiredAccess |= FILE_READ_ACCESS;
        dwFlag = FILE_OPEN_IF;
    }

    InitializeObjectAttributes(&attr, &NtFileName, OBJ_CASE_INSENSITIVE, 0, NULL);

    __try {
        Status = NtCreateFile(&hFile, DesiredAccess, &attr,
            &IoStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, dwFlag,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);

        if (!NT_SUCCESS(Status))
            __leave;

        pPosition = NULL;

        if (Append != FALSE) {
            Position.LowPart = FILE_WRITE_TO_END_OF_FILE;
            Position.HighPart = -1;
            pPosition = &Position;
        }

        if (Size < 0x80000000) {
            BlockSize = (ULONG)Size;
            Status = NtWriteFile(hFile, 0, NULL, NULL, &IoStatus, ptr, BlockSize, pPosition, NULL);
            if (!NT_SUCCESS(Status))
                __leave;

            BytesWritten += IoStatus.Information;
        }
        else {
            BlockSize = 0x7FFFFFFF;
            nBlocks = (Size / BlockSize);
            for (BlockIndex = 0; BlockIndex < nBlocks; BlockIndex++) {

                Status = NtWriteFile(hFile, 0, NULL, NULL, &IoStatus, ptr, BlockSize, pPosition, NULL);
                if (!NT_SUCCESS(Status))
                    __leave;

                ptr += BlockSize;
                BytesWritten += IoStatus.Information;
            }
            RemainingSize = (ULONG)(Size % BlockSize);
            if (RemainingSize != 0) {
                Status = NtWriteFile(hFile, 0, NULL, NULL, &IoStatus, ptr, RemainingSize, pPosition, NULL);
                if (!NT_SUCCESS(Status))
                    __leave;
                BytesWritten += IoStatus.Information;
            }
        }
    }
    __finally {
        if (hFile != NULL) {
            if (Flush != FALSE) NtFlushBuffersFile(hFile, &IoStatus);
            NtClose(hFile);
        }
        RtlFreeUnicodeString(&NtFileName);
        if (Result) *Result = Status;
    }
    return BytesWritten;
}

/*
* supGetProcAddress
*
* Purpose:
*
* Get NtOskrnl procedure address.
*
*/
ULONG_PTR supGetProcAddress(
    _In_ ULONG_PTR KernelBase,
    _In_ ULONG_PTR KernelImage,
    _In_ LPCSTR FunctionName
)
{
    ANSI_STRING    cStr;
    ULONG_PTR      pfn = 0;

    RtlInitString(&cStr, FunctionName);
    if (!NT_SUCCESS(LdrGetProcedureAddress((PVOID)KernelImage, &cStr, 0, (PVOID*)&pfn)))
        return 0;

    return KernelBase + (pfn - KernelImage);
}

/*
* supResolveKernelImport
*
* Purpose:
*
* Resolve import (ntoskrnl only).
*
*/
void supResolveKernelImport(
    _In_ ULONG_PTR Image,
    _In_ ULONG_PTR KernelImage,
    _In_ ULONG_PTR KernelBase
)
{
    PIMAGE_OPTIONAL_HEADER      popth;
    ULONG_PTR                   ITableVA, * nextthunk;
    PIMAGE_IMPORT_DESCRIPTOR    ITable;
    PIMAGE_THUNK_DATA           pthunk;
    PIMAGE_IMPORT_BY_NAME       pname;
    ULONG                       i;

    popth = &RtlImageNtHeader((PVOID)Image)->OptionalHeader;

    if (popth->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT)
        return;

    ITableVA = popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (ITableVA == 0)
        return;

    ITable = (PIMAGE_IMPORT_DESCRIPTOR)(Image + ITableVA);

    if (ITable->OriginalFirstThunk == 0)
        pthunk = (PIMAGE_THUNK_DATA)(Image + ITable->FirstThunk);
    else
        pthunk = (PIMAGE_THUNK_DATA)(Image + ITable->OriginalFirstThunk);

    for (i = 0; pthunk->u1.Function != 0; i++, pthunk++) {
        nextthunk = (PULONG_PTR)(Image + ITable->FirstThunk);
        if ((pthunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) == 0) {
            pname = (PIMAGE_IMPORT_BY_NAME)((PCHAR)Image + pthunk->u1.AddressOfData);
            nextthunk[i] = supGetProcAddress(KernelBase, KernelImage, pname->Name);
        }
        else
            nextthunk[i] = supGetProcAddress(KernelBase, KernelImage, (LPCSTR)(pthunk->u1.Ordinal & 0xffff));
    }
}

/*
* supDetectObjectCallback
*
* Purpose:
*
* Comparer callback routine used in objects enumeration.
*
*/
NTSTATUS NTAPI supDetectObjectCallback(
    _In_ POBJECT_DIRECTORY_INFORMATION Entry,
    _In_ PVOID CallbackParam
)
{
    POBJSCANPARAM Param = (POBJSCANPARAM)CallbackParam;

    if (Entry == NULL) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (CallbackParam == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Param->Buffer == NULL || Param->BufferSize == 0) {
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    if (Entry->Name.Buffer) {
        if (_strcmpi_w(Entry->Name.Buffer, Param->Buffer) == 0) {
            return STATUS_SUCCESS;
        }
    }
    return STATUS_UNSUCCESSFUL;
}

/*
* supEnumSystemObjects
*
* Purpose:
*
* Lookup object by name in given directory.
*
*/
NTSTATUS NTAPI supEnumSystemObjects(
    _In_opt_ LPWSTR pwszRootDirectory,
    _In_opt_ HANDLE hRootDirectory,
    _In_ PENUMOBJECTSCALLBACK CallbackProc,
    _In_opt_ PVOID CallbackParam
)
{
    ULONG               ctx, rlen;
    HANDLE              hDirectory = NULL;
    NTSTATUS            status;
    NTSTATUS            CallbackStatus;
    OBJECT_ATTRIBUTES   attr;
    UNICODE_STRING      sname;

    POBJECT_DIRECTORY_INFORMATION    objinf;

    if (CallbackProc == NULL) {
        return STATUS_INVALID_PARAMETER_4;
    }

    status = STATUS_UNSUCCESSFUL;

    __try {

        // We can use root directory.
        if (pwszRootDirectory != NULL) {
            RtlSecureZeroMemory(&sname, sizeof(sname));
            RtlInitUnicodeString(&sname, pwszRootDirectory);
            InitializeObjectAttributes(&attr, &sname, OBJ_CASE_INSENSITIVE, NULL, NULL);
            status = NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &attr);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        else {
            if (hRootDirectory == NULL) {
                return STATUS_INVALID_PARAMETER_2;
            }
            hDirectory = hRootDirectory;
        }

        // Enumerate objects in directory.
        ctx = 0;
        do {

            rlen = 0;
            status = NtQueryDirectoryObject(hDirectory, NULL, 0, TRUE, FALSE, &ctx, &rlen);
            if (status != STATUS_BUFFER_TOO_SMALL)
                break;

            objinf = (POBJECT_DIRECTORY_INFORMATION)supHeapAlloc(rlen);
            if (objinf == NULL)
                break;

            status = NtQueryDirectoryObject(hDirectory, objinf, rlen, TRUE, FALSE, &ctx, &rlen);
            if (!NT_SUCCESS(status)) {
                supHeapFree(objinf);
                break;
            }

            CallbackStatus = CallbackProc(objinf, CallbackParam);

            supHeapFree(objinf);

            if (NT_SUCCESS(CallbackStatus)) {
                status = STATUS_SUCCESS;
                break;
            }

        } while (TRUE);

        if (hDirectory != NULL) {
            NtClose(hDirectory);
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_ACCESS_VIOLATION;
    }

    return status;
}

/*
* supIsObjectExists
*
* Purpose:
*
* Return TRUE if the given object exists, FALSE otherwise.
*
*/
BOOLEAN supIsObjectExists(
    _In_ LPWSTR RootDirectory,
    _In_ LPWSTR ObjectName
)
{
    OBJSCANPARAM Param;

    if (ObjectName == NULL) {
        return FALSE;
    }

    Param.Buffer = ObjectName;
    Param.BufferSize = (ULONG)_strlen(ObjectName);

    return NT_SUCCESS(supEnumSystemObjects(RootDirectory, NULL, supDetectObjectCallback, &Param));
}

/*
* supQueryObjectFromHandle
*
* Purpose:
*
* Return object kernel address from handle in current process handle table.
*
*/
BOOL supQueryObjectFromHandle(
    _In_ HANDLE hOject,
    _Out_ ULONG_PTR* Address
)
{
    BOOL   bFound = FALSE;
    ULONG  i;
    DWORD  CurrentProcessId = GetCurrentProcessId();

    PSYSTEM_HANDLE_INFORMATION_EX pHandles;

    if (Address)
        *Address = 0;
    else
        return FALSE;

    pHandles = (PSYSTEM_HANDLE_INFORMATION_EX)supGetSystemInfo(SystemExtendedHandleInformation);
    if (pHandles) {
        for (i = 0; i < pHandles->NumberOfHandles; i++) {
            if (pHandles->Handles[i].UniqueProcessId == CurrentProcessId) {
                if (pHandles->Handles[i].HandleValue == (USHORT)(ULONG_PTR)hOject) {
                    *Address = (ULONG_PTR)pHandles->Handles[i].Object;
                    bFound = TRUE;
                    break;
                }
            }
        }
        supHeapFree(pHandles);
    }
    return bFound;
}

/*
* supGetCommandLineOption
*
* Purpose:
*
* Parse command line options.
*
*/
BOOL supGetCommandLineOption(
    _In_ LPCTSTR OptionName,
    _In_ BOOL IsParametric,
    _Inout_opt_ LPTSTR OptionValue,
    _In_ ULONG ValueSize
)
{
    LPTSTR	cmdline = GetCommandLine();
    TCHAR   Param[MAX_PATH + 1];
    ULONG   rlen;
    int		i = 0;

    RtlSecureZeroMemory(Param, sizeof(Param));
    while (GetCommandLineParam(cmdline, i, Param, MAX_PATH, &rlen))
    {
        if (rlen == 0)
            break;

        if (_strcmp(Param, OptionName) == 0)
        {
            if (IsParametric)
                return GetCommandLineParam(cmdline, i + 1, OptionValue, ValueSize, &rlen);

            return TRUE;
        }
        ++i;
    }

    return 0;
}

/*
* supQueryHVCIState
*
* Purpose:
*
* Query HVCI/IUM state.
*
*/
BOOLEAN supQueryHVCIState(
    _Out_ PBOOLEAN pbHVCIEnabled,
    _Out_ PBOOLEAN pbHVCIStrictMode,
    _Out_ PBOOLEAN pbHVCIIUMEnabled
)
{
    BOOLEAN hvciEnabled;
    ULONG ReturnLength;
    SYSTEM_CODEINTEGRITY_INFORMATION CodeIntegrity;

    if (pbHVCIEnabled) *pbHVCIEnabled = FALSE;
    if (pbHVCIStrictMode) *pbHVCIStrictMode = FALSE;
    if (pbHVCIIUMEnabled) *pbHVCIIUMEnabled = FALSE;

    CodeIntegrity.Length = sizeof(CodeIntegrity);
    if (NT_SUCCESS(NtQuerySystemInformation(
        SystemCodeIntegrityInformation,
        &CodeIntegrity,
        sizeof(CodeIntegrity),
        &ReturnLength)))
    {
        hvciEnabled = ((CodeIntegrity.CodeIntegrityOptions & CODEINTEGRITY_OPTION_ENABLED) &&
            (CodeIntegrity.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED));

        if (pbHVCIEnabled)
            *pbHVCIEnabled = hvciEnabled;

        if (pbHVCIStrictMode)
            *pbHVCIStrictMode = hvciEnabled &&
            (CodeIntegrity.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED);

        if (pbHVCIIUMEnabled)
            *pbHVCIIUMEnabled = (CodeIntegrity.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED) > 0;

        return TRUE;
    }

    return FALSE;
}

/*
* supExpandEnvironmentStrings
*
* Purpose:
*
* Reimplemented ExpandEnvironmentStrings.
*
*/
DWORD supExpandEnvironmentStrings(
    _In_ LPCWSTR lpSrc,
    _Out_writes_to_opt_(nSize, return) LPWSTR lpDst,
    _In_ DWORD nSize
)
{
    NTSTATUS Status;
    SIZE_T SrcLength = 0, ReturnLength = 0, DstLength = (SIZE_T)nSize;

    if (lpSrc) {
        SrcLength = _strlen(lpSrc);
    }

    Status = RtlExpandEnvironmentStrings(
        NULL,
        (PWSTR)lpSrc,
        SrcLength,
        (PWSTR)lpDst,
        DstLength,
        &ReturnLength);

    if ((NT_SUCCESS(Status)) || (Status == STATUS_BUFFER_TOO_SMALL)) {

        if (ReturnLength <= MAXDWORD32)
            return (DWORD)ReturnLength;

        Status = STATUS_UNSUCCESSFUL;
    }
    RtlSetLastWin32Error(RtlNtStatusToDosError(Status));
    return 0;
}

/*
* supQueryMaximumUserModeAddress
*
* Purpose:
*
* Return maximum user mode address.
*
*/
ULONG_PTR supQueryMaximumUserModeAddress()
{
    NTSTATUS ntStatus;

    SYSTEM_BASIC_INFORMATION basicInfo;

    ULONG returnLength = 0;
    SYSTEM_INFO systemInfo;

    RtlSecureZeroMemory(&basicInfo, sizeof(basicInfo));

    ntStatus = NtQuerySystemInformation(SystemBasicInformation,
        &basicInfo,
        sizeof(basicInfo),
        &returnLength);

    if (NT_SUCCESS(ntStatus)) {
        return basicInfo.MaximumUserModeAddress;
    }
    else {

        RtlSecureZeroMemory(&systemInfo, sizeof(systemInfo));
        GetSystemInfo(&systemInfo);
        return (ULONG_PTR)systemInfo.lpMaximumApplicationAddress;
    }

}

/*
* supFindPattern
*
* Purpose:
*
* Lookup pattern in buffer.
*
*/
PVOID supFindPattern(
    _In_ CONST PBYTE Buffer,
    _In_ SIZE_T BufferSize,
    _In_ CONST PBYTE Pattern,
    _In_ SIZE_T PatternSize
)
{
    PBYTE p0 = Buffer, pnext;

    if (PatternSize == 0)
        return NULL;

    if (BufferSize < PatternSize)
        return NULL;

    do {
        pnext = (PBYTE)memchr(p0, Pattern[0], BufferSize);
        if (pnext == NULL)
            break;

        BufferSize -= (ULONG_PTR)(pnext - p0);

        if (BufferSize < PatternSize)
            return NULL;

        if (memcmp(pnext, Pattern, PatternSize) == 0)
            return pnext;

        p0 = pnext + 1;
        --BufferSize;
    } while (BufferSize > 0);

    return NULL;
}

/*
* supGetCurrentProcessToken
*
* Purpose:
*
* Return current process token value with TOKEN_QUERY access right.
*
*/
HANDLE supGetCurrentProcessToken(
    VOID)
{
    HANDLE hToken = NULL;

    if (NT_SUCCESS(NtOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_QUERY,
        &hToken)))
    {
        return hToken;
    }
    return NULL;
}

/*
* supUserIsFullAdmin
*
* Purpose:
*
* Tests if the current user is admin with full access token.
*
*/
BOOL supUserIsFullAdmin(
    VOID
)
{
    BOOL     bResult = FALSE;
    HANDLE   hToken = NULL;
    NTSTATUS status;
    DWORD    i, Attributes;
    ULONG    ReturnLength = 0;

    PTOKEN_GROUPS pTkGroups;

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup = NULL;

    hToken = supGetCurrentProcessToken();
    if (hToken == NULL)
        return FALSE;

    do {
        if (!NT_SUCCESS(RtlAllocateAndInitializeSid(
            &NtAuthority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &AdministratorsGroup)))
        {
            break;
        }

        status = NtQueryInformationToken(hToken, TokenGroups, NULL, 0, &ReturnLength);
        if (status != STATUS_BUFFER_TOO_SMALL)
            break;

        pTkGroups = (PTOKEN_GROUPS)supHeapAlloc((SIZE_T)ReturnLength);
        if (pTkGroups == NULL)
            break;

        status = NtQueryInformationToken(hToken, TokenGroups, pTkGroups, ReturnLength, &ReturnLength);
        if (NT_SUCCESS(status)) {
            if (pTkGroups->GroupCount > 0)
                for (i = 0; i < pTkGroups->GroupCount; i++) {
                    Attributes = pTkGroups->Groups[i].Attributes;
                    if (RtlEqualSid(AdministratorsGroup, pTkGroups->Groups[i].Sid))
                        if (
                            (Attributes & SE_GROUP_ENABLED) &&
                            (!(Attributes & SE_GROUP_USE_FOR_DENY_ONLY))
                            )
                        {
                            bResult = TRUE;
                            break;
                        }
                }
        }
        supHeapFree(pTkGroups);

    } while (FALSE);

    if (AdministratorsGroup != NULL) {
        RtlFreeSid(AdministratorsGroup);
    }

    NtClose(hToken);
    return bResult;
}

/*
* supQueryTokenUserSid
*
* Purpose:
*
* Return SID of given token.
*
* Use supHeapFree to free memory allocated for result.
*
*/
PSID supQueryTokenUserSid(
    _In_ HANDLE ProcessToken
)
{
    PSID resultSid = NULL;
    PTOKEN_USER ptu;
    NTSTATUS status;
    ULONG sidLength = 0, allocLength;

    status = NtQueryInformationToken(
        ProcessToken,
        TokenUser,
        NULL, 0, &sidLength);

    if (status == STATUS_BUFFER_TOO_SMALL) {

        ptu = (PTOKEN_USER)supHeapAlloc(sidLength);

        if (ptu) {

            status = NtQueryInformationToken(
                ProcessToken,
                TokenUser,
                ptu,
                sidLength,
                &sidLength);

            if (NT_SUCCESS(status)) {

                allocLength = SECURITY_MAX_SID_SIZE;
                if (sidLength > allocLength)
                    allocLength = sidLength;

                resultSid = (PSID)supHeapAlloc(allocLength);
                if (resultSid) {

                    status = RtlCopySid(
                        allocLength,
                        resultSid,
                        ptu->User.Sid);

                }
            }

            supHeapFree(ptu);
        }
    }

    return (NT_SUCCESS(status)) ? resultSid : NULL;
}

/*
* supGetTokenInfo
*
* Purpose:
*
* Returns buffer with token information by given TokenInformationClass.
*
* Returned buffer must be freed with supHeapFree after usage.
*
*/
PVOID supGetTokenInfo(
    _In_ HANDLE TokenHandle,
    _In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
    _Out_opt_ PULONG ReturnLength
)
{
    PVOID Buffer = NULL;
    ULONG returnLength = 0;

    if (ReturnLength)
        *ReturnLength = 0;

    NtQueryInformationToken(TokenHandle,
        TokenInformationClass,
        NULL,
        0,
        &returnLength);

    Buffer = supHeapAlloc((SIZE_T)returnLength);
    if (Buffer) {

        if (NT_SUCCESS(NtQueryInformationToken(TokenHandle,
            TokenInformationClass,
            Buffer,
            returnLength,
            &returnLength)))
        {
            if (ReturnLength)
                *ReturnLength = returnLength;
            return Buffer;
        }
        else {
            supHeapFree(Buffer);
            return NULL;
        }
    }

    return Buffer;
}

/*
* supGetImageVersionInfo
*
* Purpose:
*
* Return version numbers from version info.
*
*/
BOOL supGetImageVersionInfo(
    _In_ PWSTR lpFileName,
    _In_ PSUP_VERINFO_NUMBERS VersionNumbers
)
{
    BOOL bResult = FALSE;
    DWORD dwHandle, dwSize, dwError = ERROR_SUCCESS;
    PVOID vinfo = NULL;
    UINT Length;
    VS_FIXEDFILEINFO* pFileInfo;

    dwHandle = 0;
    dwSize = GetFileVersionInfoSize(lpFileName, &dwHandle);
    if (dwSize) {
        vinfo = supHeapAlloc(dwSize);
        if (vinfo) {
            if (GetFileVersionInfoEx(0, lpFileName, 0, dwSize, vinfo)) {
                bResult = VerQueryValue(vinfo, TEXT("\\"), (LPVOID*)&pFileInfo, (PUINT)&Length);
                if (bResult) {
                    VersionNumbers->VersionMS = pFileInfo->dwFileVersionMS;
                    VersionNumbers->VersionLS = pFileInfo->dwFileVersionLS;
                }
                else {
                    dwError = GetLastError();
                }
            }
            else {
                dwError = GetLastError();
            }
            supHeapFree(vinfo);
        }
        else {
            dwError = GetLastError();
        }
    }
    else {
        dwError = GetLastError();
    }

    SetLastError(dwError);
    return bResult;
}
