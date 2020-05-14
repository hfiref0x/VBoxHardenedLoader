/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2020
*
*  TITLE:       MAIN.C
*
*  VERSION:     2.01
*
*  DATE:        10 May 2020
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

#pragma data_seg("shrd")
volatile LONG           g_lApplicationInstances = 0;
#pragma data_seg()

#define T_PROGRAMTITLE  "VirtualBox Hardened Loader v2.0.1.2005"

ULONG_PTR               g_MaximumUserModeAddress = 0;

TABLE_DESC              g_PatchData = { NULL, 0 };

//
// Help output.
//
#define T_HELP	"Loader for Tsugumi monitoring driver.\r\n\r\n\
Optional parameters to execute: \r\n\r\n\
LOADER [/s] or [/c] Table\r\n\r\n\
  /s - stop monitoring and purge system cache.\r\n\
  /c [Table] - optional, custom VBoxDD patch table fullpath.\r\n\r\n\
  Example: ldr.exe /c vboxdd.bin"

/*
* ShowVirtualBoxVesion
*
* Purpose:
*
* Read version from registry and output to console.
*
*/
VOID ShowVirtualBoxVersion()
{
    HKEY    hKey = NULL;
    LRESULT lRet;
    DWORD   dwSize;
    TCHAR   szBuffer[MAX_PATH + 1];

    //
    // Failures are non critical.
    //
    lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("Software\\Oracle\\VirtualBox"),
        0, KEY_READ, &hKey);

    if (lRet == ERROR_SUCCESS) {

        //
        // Read VBox version.
        //
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        dwSize = MAX_PATH * sizeof(TCHAR);
        lRet = RegQueryValueEx(hKey, TEXT("Version"), NULL, NULL, (LPBYTE)&szBuffer, &dwSize);
        if (lRet == ERROR_SUCCESS) {
            printf_s("LDR: VirtualBox version %wS\r\n", szBuffer);
        }

        RegCloseKey(hKey);
    }
}

/*
* FetchCustomPatchData
*
* Purpose:
*
* Load custom patch table.
* Returned buffer must be freed with HeapFree after usage.
*
*/
PVOID FetchCustomPatchData(
    _In_ LPWSTR lpFileName,
    _Inout_opt_ PDWORD pdwPatchDataSize
)
{
    DWORD   dwFileSize;
    HANDLE  hFile;
    PVOID   DataBuffer = NULL;

    LARGE_INTEGER FileSize;

    //
    // Validate input parameter.
    //
    if (lpFileName == NULL)
        return NULL;

    //
    // Open file with custom patch table.
    //
    hFile = CreateFile(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return NULL;

    //
    // Get file size for buffer, allocate it and read data.
    //
    RtlSecureZeroMemory(&FileSize, sizeof(LARGE_INTEGER));
    if (GetFileSizeEx(hFile, &FileSize)) {
        dwFileSize = FileSize.LowPart;
        if (dwFileSize > 0 && dwFileSize <= MAX_CONFIGURATION_DATA_SIZE) {
            DataBuffer = (PVOID)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
            if (DataBuffer != NULL) {

                if (ReadFile(hFile, DataBuffer, dwFileSize, &dwFileSize, NULL)) {

                    // Check if optional parameter is set and return data size on true.
                    if (pdwPatchDataSize != NULL) {
                        *pdwPatchDataSize = dwFileSize;
                    }
                }
            }
        }
    }
    CloseHandle(hFile);
    return DataBuffer;
}

/*
* CreatePatchTable
*
* Purpose:
*
* Create patch table depending on installed VBox dll.
*
*/
BOOL CreatePatchTable(
    VOID
)
{
    BOOL    bResult = FALSE;
    DWORD   dwSize, cch;
    HKEY    hKey = NULL;
    LRESULT lRet;
    TCHAR   szBuffer[MAX_PATH * 2], szTempFile[MAX_PATH * 2];

    do {

        lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("Software\\Oracle\\VirtualBox"),
            0, KEY_READ, &hKey);

        //
        // If key not exists, return FALSE and loader will exit.
        //
        if ((lRet != ERROR_SUCCESS) || (hKey == NULL)) {
            printf_s("LDR: Cannot open VirtualBox registry key, error %lli\r\n", lRet);
            break;
        }

        //
        // Read VBox location.
        //
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        dwSize = MAX_PATH * sizeof(TCHAR);
        lRet = RegQueryValueEx(hKey, TEXT("InstallDir"), NULL, NULL, (LPBYTE)&szBuffer, &dwSize);
        if (lRet != ERROR_SUCCESS) {
            printf_s("LDR: Cannot query VirtualBox installation directory, error %lli\r\n", lRet);
            break;
        }

        _strcat(szBuffer, TEXT("VBoxDD.dll"));

        RtlSecureZeroMemory(szTempFile, sizeof(szTempFile));
        cch = supExpandEnvironmentStrings(TEXT("%temp%\\"), szTempFile, MAX_PATH);
        if ((cch != 0) && (cch < MAX_PATH)) {
            //
            // Give VBoxDD.dll new name in %temp% so it won't get patched if monitor already loaded.
            //
            _strcat(szTempFile, L"nyan.dll");
            if (CopyFile(szBuffer, szTempFile, FALSE) == FALSE) {
                printf_s("LDR: Cannot copy VBoxDD to the temp folder, error %lu\r\n", GetLastError());
                break;
            }

            TABLE_DESC localTable;

            localTable.DDTablePointer = NULL;
            localTable.DDTableSize = 0;
            if (ProcessVirtualBoxFile(szTempFile, &localTable.DDTablePointer, &localTable.DDTableSize) == 0) {

                if (localTable.DDTableSize > MAX_CONFIGURATION_DATA_SIZE) {
                    printf_s("LDR: Patch data size %lu exceed data size limit %lu\r\n",
                        localTable.DDTableSize,
                        MAX_CONFIGURATION_DATA_SIZE);
                }
                else {
                    g_PatchData.DDTablePointer = localTable.DDTablePointer;
                    g_PatchData.DDTableSize = localTable.DDTableSize;
                    bResult = TRUE;
                }
            }
            else {
                printf_s("LDR: Error while processing VBoxDD file\r\n");
            }

            //
            // Remove nyan.dll from %temp%.
            //
            DeleteFile(szTempFile);
        }
        else {
            printf_s("LDR: Could not expand environment variable for temp directory\r\n");
        }

    } while (FALSE);

    if (hKey) {
        RegCloseKey(hKey);
    }

    return bResult;
}

/*
* ListTokenPrivileges
*
* Purpose:
*
* List all available privileges of current process token.
*
*/
VOID ListTokenPrivileges()
{
    PTOKEN_PRIVILEGES pTokenPrivs;
    HANDLE TokenHandle = supGetCurrentProcessToken();

    WCHAR szPrivName[MAX_PATH + 1];
    ULONG cchName;

    BOOLEAN Enabled, EnabledByDefault;

    printf_s(T_PRNTDEFAULT, "LDR: Listing process token privileges...");

    if (TokenHandle) {

        pTokenPrivs = (PTOKEN_PRIVILEGES)supGetTokenInfo(TokenHandle,
            TokenPrivileges,
            NULL);

        if (pTokenPrivs) {

            for (ULONG i = 0; i < pTokenPrivs->PrivilegeCount; i++) {

                //
                // Output privilege flags like Process Explorer.
                //
                szPrivName[0] = 0;
                cchName = MAX_PATH;
                if (LookupPrivilegeName(NULL, &pTokenPrivs->Privileges[i].Luid,
                    szPrivName, &cchName))
                {
                    Enabled = pTokenPrivs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED;
                    EnabledByDefault = pTokenPrivs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT;

                    printf_s("LDR: %ws %s %s\r\n",
                        szPrivName,
                        Enabled ? "Enabled" : "Disabled",
                        EnabledByDefault ? "(Default Enabled)" : "");

                }

            }

            supHeapFree(pTokenPrivs);
        }
        else {
            printf_s(T_PRNTDEFAULT, "[!] Could not query token privileges");
        }
        NtClose(TokenHandle);
    }

}

/*
* AssignPrivileges
*
* Purpose:
*
* Assign required privileges.
*
*/
BOOLEAN AssignPrivileges(
    _In_ BOOLEAN IsDebugRequired
)
{
    NTSTATUS ntStatus;

    if (IsDebugRequired) {
        ntStatus = supEnablePrivilege(SE_DEBUG_PRIVILEGE, TRUE);
        if (!NT_SUCCESS(ntStatus)) {
            printf_s("[!] Abort: SeDebugPrivilege is not assigned! NTSTATUS (0x%lX)\r\n", ntStatus);
            return FALSE;
        }
        else {
            printf_s("LDR: SeDebugPrivilege assigned\r\n");
        }
    }

    ntStatus = supEnablePrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE);
    if (!NT_SUCCESS(ntStatus)) {
        printf_s("[!] Abort: SeLoadDriverPrivilege is not assigned! NTSTATUS (0x%lX)\r\n", ntStatus);
        return FALSE;
    }
    else {
        printf_s("LDR: SeLoadDriverPrivilege assigned\r\n");
    }

    return TRUE;
}

/*
* VBoxLdrMain
*
* Purpose:
*
* Program main.
*
*/
int VBoxLdrMain(
    VOID
)
{
    BOOL  bCustomTableAllocated = FALSE;
    LONG  x;
    ULONG dataLength = 0;
    PVOID DataBufferDD = NULL;
    WCHAR szParameter[MAX_PATH * 2];

    OSVERSIONINFO osv;

    printf_s("[>] Entering %s\r\n", __FUNCTION__);

#ifdef _DEBUG
    printf_s(T_PRNTDEFAULT, "[!] Debug build!");
#endif

    do {

        //
        // Check number of instances running.
        //
        x = InterlockedIncrement((PLONG)&g_lApplicationInstances);
        if (x > 1) {
            break;
        }

        //
        // Check OS version.
        //
        RtlSecureZeroMemory(&osv, sizeof(osv));
        osv.dwOSVersionInfoSize = sizeof(osv);
        RtlGetVersion((PRTL_OSVERSIONINFOW)&osv);
        if (osv.dwMajorVersion < 6) {
            printf_s(T_PRNTDEFAULT, "LDR: This operation system version is not supported");
            break;
        }

        if (!supUserIsFullAdmin()) {
            printf_s(T_PRNTDEFAULT, "[!] No administrator rights or runs not elevated, program will fail");
        }
        else {
            ListTokenPrivileges();
        }

        ShowVirtualBoxVersion();

        CHAR szVersion[100];

        StringCchPrintfA(szVersion, 100,
            "LDR: Windows version: %u.%u build %u",
            osv.dwMajorVersion,
            osv.dwMinorVersion,
            osv.dwBuildNumber);

        printf_s(T_PRNTDEFAULT, szVersion);

        g_MaximumUserModeAddress = supQueryMaximumUserModeAddress();
        printf_s("LDR: Maximum User Mode address 0x%llX\r\n", g_MaximumUserModeAddress);

        BOOLEAN hvciEnabled;
        BOOLEAN hvciStrict;
        BOOLEAN hvciIUM;

        //
        // Provider is not HVCI compatible.
        //
        if (supQueryHVCIState(&hvciEnabled, &hvciStrict, &hvciIUM)) {

            if (hvciEnabled) {
                printf_s(T_PRNTDEFAULT, "[!] Windows HVCI mode detected - this is unsupported");
                break;
            }

        }

        //
        // Parse command line, can only be /s /c or /? 
        //

        //
        // Stop
        //
        if (supGetCommandLineOption(TEXT("/s"),
            FALSE,
            NULL,
            0))
        {
            printf_s(T_PRNTDEFAULT, "LDR: Monitor stop selected");

            if (AssignPrivileges(FALSE)) {
                VictimRelease((LPWSTR)PROCEXP152);
                printf_s(T_PRNTDEFAULT, "LDR: Purging system cache");
                supPurgeSystemCache();
            }
            break;
        }
        else {
            //
            // Custom table.
            //

            RtlSecureZeroMemory(szParameter, sizeof(szParameter));

            if (supGetCommandLineOption(TEXT("/c"),
                TRUE,
                szParameter,
                sizeof(szParameter) / sizeof(WCHAR)))
            {
                dataLength = 0;
                DataBufferDD = FetchCustomPatchData(szParameter, &dataLength);
                if ((DataBufferDD != NULL) && (dataLength > 0)) {
                    g_PatchData.DDTablePointer = DataBufferDD;
                    g_PatchData.DDTableSize = dataLength;
                    bCustomTableAllocated = TRUE;
                    printf_s(T_PRNTDEFAULT, "LDR: Custom patch table loaded");
                }
                else {
                    printf_s(T_PRNTDEFAULT, "LDR: Error reading specfied file");
                    break;
                }

            }
            else {
                //
                // Help.
                //
                if (supGetCommandLineOption(TEXT("/?"),
                    FALSE,
                    NULL,
                    0))
                {
                    printf_s(T_PRNTDEFAULT, T_HELP);
                    break;
                }
            }
        }


        //
        // Check if custom patch table present. If not - attempt to create own. Exit on failure.
        //
        if (bCustomTableAllocated == FALSE) {
            if (CreatePatchTable()) {
                printf_s(T_PRNTDEFAULT, "LDR: Patch table created");
            }
            else {
                printf_s(T_PRNTDEFAULT, "LDR: Could not load patch table");
                break;
            }
        }

#ifndef _DEBUG
        //
        // Check if any VBox instances are running, they must be closed before our usage.
        //
        if (supProcessExist(L"VirtualBox.exe")) {
            printf_s(T_PRNTDEFAULT, "LDR: VirtualBox is running, close it before");
            break;
        }
#endif

        if (AssignPrivileges(TRUE)) {

            if (!MapTsugumi(&g_PatchData)) {
                printf_s(T_PRNTDEFAULT, "LDR: Cannot inject monitor code");
                break;
            }
            else {
                printf_s(T_PRNTDEFAULT, "LDR: Monitor code injected and executed");
                printf_s(T_PRNTDEFAULT, "LDR: Purging system cache");
                supPurgeSystemCache();
            }

        }

    } while (FALSE);

    printf_s("[<] Leaving %s\r\n", __FUNCTION__);
    InterlockedDecrement((PLONG)&g_lApplicationInstances);
    return 1;
}


/*
* main
*
* Purpose:
*
* Program entry point.
*
*/
int main()
{
    HeapSetInformation(NULL, HeapEnableTerminationOnCorruption, NULL, 0);

    printf_s(T_PRNTDEFAULT, T_PROGRAMTITLE);

    return VBoxLdrMain();
}
