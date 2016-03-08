/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2016
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.50
*
*  DATE:        06 Mar 2016
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "tables.h"
#include <process.h>

#pragma data_seg("shrd")
volatile LONG           g_lApplicationInstances = 0;
#pragma data_seg()

#define TsmiParamsKey   L"Parameters"
#define TsmiPatchData   L"PatchData"
#define T_PROGRAMTITLE  L"VBoxLoader"

ULONG                   g_TsmiPatchDataValueSize;
PVOID                   g_TsmiPatchDataValue;

//
// Help output.
//
#define T_HELP	L"VirtualBox Hardened Loader v1.5.6000\n\n\r\
loader [CustomPatchTable]\n\r\
[CustomPatchTable] Optional parameter - table filename with full path.\n\n\r\
Example: ldr.exe mydata.bin"

#define MAXIMUM_SUPPORTED_VERSIONS 6
TABLE_DESC g_Tables[MAXIMUM_SUPPORTED_VERSIONS] = {
    { L"5.0.0", TsmiPatchDataValue_500, sizeof(TsmiPatchDataValue_500) },
    { L"5.0.2", TsmiPatchDataValue_502, sizeof(TsmiPatchDataValue_502) },
    { L"5.0.8", TsmiPatchDataValue_508, sizeof(TsmiPatchDataValue_508) },
    { L"5.0.10", TsmiPatchDataValue_5010, sizeof(TsmiPatchDataValue_5010) },
    { L"5.0.12", TsmiPatchDataValue_5012, sizeof(TsmiPatchDataValue_5012) },
    { L"5.0.16", TsmiPatchDataValue_5016, sizeof(TsmiPatchDataValue_5016) }
};

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
	LRESULT lRet;

	hRootKey = NULL;
	hParamsKey = NULL;

	do {

		lRet = RegCreateKeyEx(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\Tsugumi", 0, NULL, 0, KEY_ALL_ACCESS,
			NULL, &hRootKey, NULL);

		if ((lRet != ERROR_SUCCESS) || (hRootKey == NULL)) {
			break;
		}

		lRet = RegCreateKey(hRootKey, TsmiParamsKey, &hParamsKey);
		if ((lRet != ERROR_SUCCESS) || (hParamsKey == NULL)) {
			break;
		}

		lRet = RegSetValueEx(hParamsKey, TsmiPatchData, 0, REG_BINARY, 
			(LPBYTE)g_TsmiPatchDataValue, g_TsmiPatchDataValueSize);

        bResult = (lRet == ERROR_SUCCESS);

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
	BOOL     cond = FALSE;
	DWORD    dwSize;
	HKEY     hKey = NULL;
	LRESULT  lRet;
    INT      i;

	TCHAR	szBuffer[MAX_PATH + 1];

	do {
		//
		// Select default patch table.
		//
		g_TsmiPatchDataValue = TsmiPatchDataValue_5016;
		g_TsmiPatchDataValueSize = sizeof(TsmiPatchDataValue_5016);

		lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("Software\\Oracle\\VirtualBox"), 
			0, KEY_READ, &hKey);
	
		//
		// If key not exists, return FALSE and loader will exit.
		//
		if ((lRet != ERROR_SUCCESS) || (hKey == NULL)) {
			break;
		}

		//
		// Read VBox version and select proper table.
		//
		RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
		dwSize = MAX_PATH * sizeof(TCHAR);
		lRet = RegQueryValueEx(hKey, TEXT("Version"), NULL, NULL, (LPBYTE)&szBuffer, &dwSize);
		if (lRet != ERROR_SUCCESS) {
			break;
		}

        for (i = 0; i < MAXIMUM_SUPPORTED_VERSIONS; i++) {
            if (_strcmpi(g_Tables[i].lpDescription, szBuffer) == 0) {
                g_TsmiPatchDataValue = g_Tables[i].TablePointer;
                g_TsmiPatchDataValueSize = g_Tables[i].TableSize;
                break;
            }
        }

	} while (cond);

	if (hKey) {
		RegCloseKey(hKey);
	}
}

/*
* ldrMain
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
	BOOL    cond = FALSE;
	LONG    x;
	ULONG   l = 0;
	PVOID   DataBuffer;
	HANDLE  hDevice;
	WCHAR   szBuffer[MAX_PATH + 1];

	__security_init_cookie();

	DataBuffer = NULL;

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
		RtlGetNtVersionNumbers(&l, NULL, NULL);

		//
		// We support only Vista based OS.
		//
		if (l < 6) {
			MessageBox(GetDesktopWindow(), TEXT("Unsupported OS."),
				T_PROGRAMTITLE, MB_ICONINFORMATION);
			break;
		}

#ifndef _DEBUG
		//
		// Check if any VBox instances are running, they must be closed before our usage.
		//
		if (supProcessExist(L"VirtualBox.exe")) {
			MessageBox(GetDesktopWindow(), TEXT("VirtualBox is running, close it before."),
				T_PROGRAMTITLE, MB_ICONINFORMATION);
			break;
		}
#endif
		SelectPatchTable();

		// Load custom patch table, if present.
		RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
		GetCommandLineParam(GetCommandLine(), 1, szBuffer, MAX_PATH, &l);
		if (l > 0) {
			l = 0;
			DataBuffer = FetchCustomPatchData(szBuffer, &l);
			if ((DataBuffer != NULL) && (l > 0)) {
				g_TsmiPatchDataValue = DataBuffer;
				g_TsmiPatchDataValueSize = l;
			}
		}

        if (!SetTsmiParams()) {
            MessageBox(GetDesktopWindow(), TEXT("Cannot write Tsugumi settings."), 
                T_PROGRAMTITLE, MB_ICONERROR);
            break;
        }

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
			DeviceIoControl(hDevice, TSUGUMI_IOCTL_REFRESH_LIST, NULL, 0, NULL, 0, &l, NULL);
			CloseHandle(hDevice);

			//force windows rebuild image cache
			supPurgeSystemCache();
		}
		else {
			MessageBox(GetDesktopWindow(), TEXT("Cannot open Tsugumi device."),
				T_PROGRAMTITLE, MB_ICONERROR);
		}

	} while (cond);

	InterlockedDecrement((PLONG)&g_lApplicationInstances);
	ExitProcess(0);
}
