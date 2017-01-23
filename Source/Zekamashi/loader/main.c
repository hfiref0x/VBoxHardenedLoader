/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.71
*
*  DATE:        19 Jan 2017
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "tables.h"

#pragma data_seg("shrd")
volatile LONG           g_lApplicationInstances = 0;
#pragma data_seg()

#define TsmiParamsKey   L"Parameters"
#define TsmiVBoxDD      L"VBoxDD.dll"
#define TsmiVBoxVMM     L"VBoxVMM.dll"

#define T_PROGRAMTITLE  L"VirtualBox Hardened Loader v1.7.1.1701"

TABLE_DESC              g_PatchData;

//
// Help output.
//
#define T_HELP	L"Sets parameters for Tsugumi driver.\n\n\r\
Optional parameters to execute: \n\n\r\
LOADER [/s] or [Table1] [Table2]\n\n\r\
  /s - stop monitoring and purge system cache.\n\r\
  Table1 - custom VBoxDD patch table fullpath.\n\r\
  Table2 - custom VBoxVMM patch table fullpath.\n\n\r\
  Example: ldr.exe vboxdd.bin vboxvmm.bin"


#define MAXIMUM_SUPPORTED_VERSIONS 10
TABLE_DESC g_Tables[MAXIMUM_SUPPORTED_VERSIONS] = {

    {
        L"5.0.16",
        TsmiPatchDataValue_5016, sizeof(TsmiPatchDataValue_5016),
        TsmiPatchDataValueVMM_5016, sizeof(TsmiPatchDataValueVMM_5016)
    },

    {
        L"5.0.22",
        TsmiPatchDataValue_5022, sizeof(TsmiPatchDataValue_5022),
        TsmiPatchDataValueVMM_5022, sizeof(TsmiPatchDataValueVMM_5022)
    },

    {
        L"5.1.0",
        TsmiPatchDataValue_5100, sizeof(TsmiPatchDataValue_5100),
        TsmiPatchDataValueVMM_5100, sizeof(TsmiPatchDataValueVMM_5100)
    },

    {
        L"5.1.2",
        TsmiPatchDataValue_5102, sizeof(TsmiPatchDataValue_5102),
        TsmiPatchDataValueVMM_5102, sizeof(TsmiPatchDataValueVMM_5102)
    },

    {
        L"5.1.4",
        TsmiPatchDataValue_5104, sizeof(TsmiPatchDataValue_5104),
        NULL, 0
    },

    {
        L"5.1.6",
        TsmiPatchDataValue_5106, sizeof(TsmiPatchDataValue_5106),
        NULL, 0
    },

    {
        L"5.1.8",
        TsmiPatchDataValue_5108, sizeof(TsmiPatchDataValue_5108),
        NULL, 0
    },


    {
        L"5.1.10",
        TsmiPatchDataValue_5110, sizeof(TsmiPatchDataValue_5110),
        NULL, 0
    },

    {
        L"5.1.12",
        TsmiPatchDataValue_5112, sizeof(TsmiPatchDataValue_5112),
        NULL, 0
    },

    {
        L"5.1.14",
        TsmiPatchDataValue_5114, sizeof(TsmiPatchDataValue_5114),
        NULL, 0
    }

};

HANDLE     g_ConOut = NULL;
BOOL       g_ConsoleOutput = FALSE;
WCHAR      BE = 0xFEFF;

/*
* SetTsmiParams
*
* Purpose:
*
* Set patch chains data to the registry.
*
*/
BOOL SetTsmiParams(
    VOID
)
{
    BOOL cond = FALSE, bResult = FALSE;
    HKEY hRootKey, hParamsKey;
    LRESULT lRet = ERROR_BAD_ARGUMENTS;

    hRootKey = NULL;
    hParamsKey = NULL;

    do {

        lRet = RegCreateKeyEx(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\Tsugumi", 0, NULL, 0, KEY_ALL_ACCESS,
            NULL, &hRootKey, NULL);

        if ((lRet != ERROR_SUCCESS) || (hRootKey == NULL)) {
            cuiPrintText(g_ConOut, TEXT("Ldr: Cannot create/open Tsugumi key"), g_ConsoleOutput, TRUE);
            break;
        }

        lRet = RegCreateKey(hRootKey, TsmiParamsKey, &hParamsKey);
        if ((lRet != ERROR_SUCCESS) || (hParamsKey == NULL)) {
            cuiPrintText(g_ConOut, TEXT("Ldr: Cannot create/open Tsugumi->Parameters key"), g_ConsoleOutput, TRUE);
            break;
        }

        lRet = ERROR_BAD_ARGUMENTS;
        if ((g_PatchData.DDTablePointer) && (g_PatchData.DDTableSize > 0)) {
            lRet = RegSetValueEx(hParamsKey, TsmiVBoxDD, 0, REG_BINARY,
                (LPBYTE)g_PatchData.DDTablePointer, g_PatchData.DDTableSize);
            if (lRet != ERROR_SUCCESS) {
                cuiPrintText(g_ConOut, TEXT("Ldr: Cannot write VBoxDD patch table"), g_ConsoleOutput, TRUE);
                break;
            }
        }
        else {
            RegDeleteValue(hParamsKey, TsmiVBoxDD);
        }

        if ((g_PatchData.VMMTablePointer) && (g_PatchData.VMMTableSize > 0)) {
            lRet = RegSetValueEx(hParamsKey, TsmiVBoxVMM, 0, REG_BINARY,
                (LPBYTE)g_PatchData.VMMTablePointer, g_PatchData.VMMTableSize);
            if (lRet != ERROR_SUCCESS) {
                cuiPrintText(g_ConOut, TEXT("Ldr: Cannot write VBoxVMM patch table"), g_ConsoleOutput, TRUE);
                break;
            }
        }
        else {
            RegDeleteValue(hParamsKey, TsmiVBoxVMM);
        }

        bResult = TRUE;

    } while (cond);

    if (hRootKey) {
        RegCloseKey(hRootKey);
    }
    if (hParamsKey) {
        RegCloseKey(hParamsKey);
    }

    return bResult;
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
    HANDLE hFile;
    DWORD dwSize;
    PVOID DataBuffer = NULL;

    //
    // Validate input parameter.
    //
    if (lpFileName == NULL) {
        return NULL;
    }

    //
    // Open file with custom patch table.
    //
    hFile = CreateFile(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    //
    // Get file size for buffer, allocate it and read data.
    //
    dwSize = GetFileSize(hFile, NULL);
    if (dwSize > 0 && dwSize <= 4096) {

        DataBuffer = (PVOID)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
        if (DataBuffer != NULL) {

            if (ReadFile(hFile, DataBuffer, dwSize, &dwSize, NULL)) {

                // Check if optional parameter is set and return data size on true.
                if (pdwPatchDataSize != NULL) {
                    *pdwPatchDataSize = dwSize;
                }
            }
        }
    }
    CloseHandle(hFile);
    return DataBuffer;
}

/*
* SelectPatchTable
*
* Purpose:
*
* Select patch table depending on installed VBox version.
*
*/
VOID SelectPatchTable(
    VOID
)
{
    BOOL     cond = FALSE, bFound = FALSE;
    DWORD    dwSize;
    HKEY     hKey = NULL;
    LRESULT  lRet;
    INT      i;

    TCHAR	szBuffer[MAX_PATH + 1];

    do {
        //
        // Select default patch table.
        //
        g_PatchData = g_Tables[MAXIMUM_SUPPORTED_VERSIONS - 1];

        lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("Software\\Oracle\\VirtualBox"),
            0, KEY_READ, &hKey);

        //
        // If key not exists, return FALSE and loader will exit.
        //
        if ((lRet != ERROR_SUCCESS) || (hKey == NULL)) {
            cuiPrintText(g_ConOut, TEXT("Ldr: Cannot open VirtualBox version key"), g_ConsoleOutput, TRUE);
            break;
        }

        //
        // Read VBox version and select proper table.
        //
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        dwSize = MAX_PATH * sizeof(TCHAR);
        lRet = RegQueryValueEx(hKey, TEXT("Version"), NULL, NULL, (LPBYTE)&szBuffer, &dwSize);
        if (lRet != ERROR_SUCCESS) {
            cuiPrintText(g_ConOut, TEXT("Ldr: Cannot query VirtualBox version"), g_ConsoleOutput, TRUE);
            break;
        }

        for (i = 0; i < MAXIMUM_SUPPORTED_VERSIONS; i++) {
            if (_strcmpi(g_Tables[i].lpDescription, szBuffer) == 0) {

                RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
                _strcpy(szBuffer, TEXT("Ldr: VirtualBox compatible version: "));
                _strcat(szBuffer, g_Tables[i].lpDescription);
                cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);
                g_PatchData = g_Tables[i];
                bFound = TRUE;
                break;
            }
        }

        if (bFound != TRUE) {
            cuiPrintText(g_ConOut, TEXT("Ldr: WARNING, compatible VirtualBox version not found, using default patch table"), g_ConsoleOutput, TRUE);
        }

    } while (cond);

    if (hKey) {
        RegCloseKey(hKey);
    }

}

/*
* SendCommand
*
* Purpose:
*
* Call Tsugumi driver with IOCTL.
*
*/
VOID SendCommand(
    DWORD dwCmd,
    LPWSTR lpCmd
)
{
    ULONG  l = 0;
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    WCHAR  szBuffer[MAX_PATH * 2];

    // Open Tsugumi instance
    hDevice = NULL;
    _strcpy(szBuffer, TSUGUMI_SYM_LINK);
    hDevice = CreateFile(szBuffer,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice != INVALID_HANDLE_VALUE) {

        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, TEXT("Ldr: Tsugumi device handle opened = "));
        u64tostr((ULONG_PTR)hDevice, _strend(szBuffer));
        cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

        DeviceIoControl(hDevice, dwCmd, NULL, 0, NULL, 0, &l, NULL);

        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, TEXT("Ldr: "));
        _strcat(szBuffer, lpCmd);
        _strcat(szBuffer, TEXT(" request"));

        if (l == 1)
            _strcat(szBuffer, TEXT(" successful"));
        else
            _strcat(szBuffer, TEXT(" failed"));
        cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

        CloseHandle(hDevice);

        if (l == 1) {
            //force windows rebuild image cache
            cuiPrintText(g_ConOut, TEXT("Ldr: purge system cache"), g_ConsoleOutput, TRUE);
            supPurgeSystemCache();
        }

    }
    else {
        cuiPrintText(g_ConOut,
            TEXT("Ldr: Cannot open Tsugumi device, make sure driver is loaded before running this program"), g_ConsoleOutput, TRUE);
    }
}


/*
* VBoxLdrMain
*
* Purpose:
*
* Program entry point.
*
*/
void VBoxLdrMain(
    VOID
)
{
    BOOL    cond = FALSE, loadVbox = FALSE;
    LONG    x;
    ULONG   l = 0, uCmd = 0;
    PVOID   DataBufferDD, DataBufferVMM;
    WCHAR   szBuffer[MAX_PATH * 2];

    __security_init_cookie();

    DataBufferDD = NULL;
    DataBufferVMM = NULL;

    do {

        g_ConOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (g_ConOut == INVALID_HANDLE_VALUE) {
            break;
        }

        g_ConsoleOutput = TRUE;
        if (!GetConsoleMode(g_ConOut, &l)) {
            g_ConsoleOutput = FALSE;
        }

        SetConsoleTitle(T_PROGRAMTITLE);
        SetConsoleMode(g_ConOut, ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_OUTPUT);
        if (g_ConsoleOutput == FALSE) {
            WriteFile(g_ConOut, &BE, sizeof(WCHAR), &l, NULL);
        }

        cuiPrintText(g_ConOut, T_PROGRAMTITLE, g_ConsoleOutput, TRUE);

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
        RtlGetNtVersionNumbers(&l, NULL, NULL);

        //
        // We support only Vista based OS.
        //
        if (l < 6) {
            cuiPrintText(g_ConOut, TEXT("Ldr: This operation system version is not supported"), g_ConsoleOutput, TRUE);
            break;
        }

        SelectPatchTable();

        // Parse command line.

        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        GetCommandLineParam(GetCommandLine(), 1, szBuffer, MAX_PATH, &l);
        if (l > 0) {

            if (_strcmpi(szBuffer, TEXT("/?")) == 0) {
                cuiPrintText(g_ConOut, T_HELP, g_ConsoleOutput, TRUE);
                break;
            }

            if (_strcmpi(szBuffer, TEXT("/s")) == 0) {
                uCmd = TSUGUMI_IOCTL_MONITOR_STOP;
            }

			if (_strcmpi(szBuffer, TEXT("/l")) == 0) {
				loadVbox = TRUE;
			}

            if (uCmd != TSUGUMI_IOCTL_MONITOR_STOP) {
                l = 0;
                DataBufferDD = FetchCustomPatchData(szBuffer, &l);
                if ((DataBufferDD != NULL) && (l > 0)) {
                    g_PatchData.DDTablePointer = DataBufferDD;
                    g_PatchData.DDTableSize = l;
                }
                else {
                    cuiPrintText(g_ConOut, TEXT("Ldr: Error reading file at parameter 1"), g_ConsoleOutput, TRUE);
                    break;
                }
            }
        }

        if (uCmd != TSUGUMI_IOCTL_MONITOR_STOP) {
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            GetCommandLineParam(GetCommandLine(), 2, szBuffer, MAX_PATH, &l);
            if (l > 0) {
                l = 0;
                DataBufferVMM = FetchCustomPatchData(szBuffer, &l);
                if ((DataBufferVMM != NULL) && (l > 0)) {
                    g_PatchData.VMMTablePointer = DataBufferVMM;
                    g_PatchData.VMMTableSize = l;
                }
                else {
                    cuiPrintText(g_ConOut, TEXT("Ldr: Error reading file at parameter 2"), g_ConsoleOutput, TRUE);
                    break;
                }
            }
        }

#ifndef _DEBUG
        //
        // Check if any VBox instances are running, they must be closed before our usage.
        //
        if (supProcessExist(L"VirtualBox.exe")) {
            cuiPrintText(g_ConOut, TEXT("Ldr: VirtualBox is running, close it before"), g_ConsoleOutput, TRUE);
            break;
        }
#endif
        if (uCmd == TSUGUMI_IOCTL_MONITOR_STOP) {
            SendCommand(TSUGUMI_IOCTL_MONITOR_STOP, TEXT("TSUGUMI_IOCTL_MONITOR_STOP"));
            break;
        }

        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, TEXT("Ldr: Patch table params -> \n\r"));
        _strcat(szBuffer, TEXT("  VBoxDD mapped table pointer = 0x"));
        u64tohex((ULONG_PTR)g_PatchData.DDTablePointer, _strend(szBuffer));
        _strcat(szBuffer, TEXT("\n\r  VBoxDD table size = 0x"));
        ultohex(g_PatchData.DDTableSize, _strend(szBuffer));

        if (g_PatchData.VMMTablePointer != NULL) {
            _strcat(szBuffer, TEXT("\n\r  VBoxVMM mapped table pointer = 0x"));
            u64tohex((ULONG_PTR)g_PatchData.VMMTablePointer, _strend(szBuffer));
        }
        if (g_PatchData.VMMTableSize != 0) {
            _strcat(szBuffer, TEXT("\n\r  VBoxVMM table size = 0x"));
            ultohex(g_PatchData.VMMTableSize, _strend(szBuffer));
        }
        cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

        if (!SetTsmiParams()) {
            cuiPrintText(g_ConOut, TEXT("Ldr: Cannot write Tsugumi settings"), g_ConsoleOutput, TRUE);
            break;
        }
        else {
            cuiPrintText(g_ConOut, TEXT("Ldr: Tsugumi patch table parameters set"), g_ConsoleOutput, TRUE);
            SendCommand(TSUGUMI_IOCTL_REFRESH_LIST, TEXT("TSUGUMI_IOCTL_REFRESH_LIST"));
        }

    } while (cond);
    cuiPrintText(g_ConOut, TEXT("Ldr: exit"), g_ConsoleOutput, TRUE);
	if (loadVbox) {
		system("sc start vboxdrv");
	}
    InterlockedDecrement((PLONG)&g_lApplicationInstances);
    ExitProcess(0);
}
