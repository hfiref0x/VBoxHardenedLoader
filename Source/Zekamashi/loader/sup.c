/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2015
*
*  TITLE:       SUP.C
*
*  VERSION:     1.20
*
*  DATE:        10 Mar 2015
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include <Shlwapi.h>
#include <ShlObj.h>
#include <netcon.h>

#define INET_CONNECTION_COUNT 1

//include for PathFileExists API
#pragma comment(lib, "shlwapi.lib")

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
	if (supEnablePrivilege(SE_INCREASE_QUOTA_PRIVILEGE, TRUE)) {
		RtlSecureZeroMemory(&sfc, sizeof(SYSTEM_FILECACHE_INFORMATION));
		sfc.MaximumWorkingSet = (SIZE_T)-1;
		sfc.MinimumWorkingSet = (SIZE_T)-1;
		NtSetSystemInformation(SystemFileCacheInformation, &sfc, sizeof(sfc));
	}

	//flush standby list
	if (supEnablePrivilege(SE_PROF_SINGLE_PROCESS_PRIVILEGE, TRUE)) {
		smlc = MemoryPurgeStandbyList;
		NtSetSystemInformation(SystemMemoryListInformation, &smlc, sizeof(smlc));
	}
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
	_Inout_ void *dest,
	_In_ size_t cbdest,
	_In_ const void *src,
	_In_ size_t cbsrc
	)
{
	char *d = (char*)dest;
	char *s = (char*)src;

	if ((dest == 0) || (src == 0) || (cbdest == 0))
		return;
	if (cbdest<cbsrc)
		cbsrc = cbdest;

	while (cbsrc>0) {
		*d++ = *s++;
		cbsrc--;
	}
}

/*
* supGetSystemInfo
*
* Purpose:
*
* Returns buffer with system information by given InfoClass.
*
* Returned buffer must be freed with HeapFree after usage.
* Function will return error after 100 attempts.
*
*/
PVOID supGetSystemInfo(
	_In_ SYSTEM_INFORMATION_CLASS InfoClass
	)
{
	INT			c = 0;
	PVOID		Buffer = NULL;
	ULONG		Size = 0x1000;
	NTSTATUS	status;
	ULONG       memIO;

	do {
		Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
		if (Buffer != NULL) {
			status = NtQuerySystemInformation(InfoClass, Buffer, Size, &memIO);
		}
		else {
			return NULL;
		}
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			HeapFree(GetProcessHeap(), 0, Buffer);
			Size *= 2;
		}
		c++;
		if (c > 100) {
			status = STATUS_SECRET_TOO_LONG;
			break;
		}
	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	if (NT_SUCCESS(status)) {
		return Buffer;
	}

	if (Buffer) {
		HeapFree(GetProcessHeap(), 0, Buffer);
	}
	return NULL;
}

/*
* supBackupVBoxDrv
*
* Purpose:
*
* Backup virtualbox driver file if it already installed.
* When bRestore is TRUE return value indicate if VBox driver 
* was already installed in system.
*
*/
BOOL supBackupVBoxDrv(
	_In_ BOOL bRestore
	)
{
	BOOL bResult = FALSE;
	WCHAR szOldDriverName[MAX_PATH * 2];
	WCHAR szNewDriverName[MAX_PATH * 2];
	WCHAR szDriverDirName[MAX_PATH * 2];

	if (!GetSystemDirectory(szDriverDirName, MAX_PATH)) {
		return FALSE;
	}
	_strcat(szDriverDirName, TEXT("\\drivers\\"));

	if (bRestore) {
		_strcpy(szOldDriverName, szDriverDirName);
		_strcat(szOldDriverName, TEXT("VBoxDrv.backup"));
		if (PathFileExists(szOldDriverName)) {
			_strcpy(szNewDriverName, szDriverDirName);
			_strcat(szNewDriverName, TEXT("VBoxDrv.sys"));
			bResult = MoveFileEx(szOldDriverName, szNewDriverName,
				MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
		}
	}
	else {
		_strcpy(szOldDriverName, szDriverDirName);
		_strcat(szOldDriverName, TEXT("VBoxDrv.sys"));

		bResult = PathFileExists(szOldDriverName);
		if (bResult) {
			_strcpy(szNewDriverName, szDriverDirName);
			_strcat(szNewDriverName, TEXT("VBoxDrv.backup"));
			MoveFileEx(szOldDriverName, szNewDriverName,
				MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
		}
	}
	return bResult;
}

/*
* supEnablePrivilege
*
* Purpose:
*
* Enable/Disable given privilege.
*
* Return FALSE on any error.
*
*/
BOOL supEnablePrivilege(
	_In_ DWORD	PrivilegeName,
	_In_ BOOL	fEnable
	)
{
	BOOL bResult = FALSE;
	NTSTATUS status;
	HANDLE hToken;
	TOKEN_PRIVILEGES TokenPrivileges;

	status = NtOpenProcessToken(
		GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken);

	if (!NT_SUCCESS(status)) {
		return bResult;
	}

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Luid.LowPart = PrivilegeName;
	TokenPrivileges.Privileges[0].Luid.HighPart = 0;
	TokenPrivileges.Privileges[0].Attributes = (fEnable) ? SE_PRIVILEGE_ENABLED : 0;
	status = NtAdjustPrivilegesToken(hToken, FALSE, &TokenPrivileges,
		sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, NULL);
	if (status == STATUS_NOT_ALL_ASSIGNED) {
		status = STATUS_PRIVILEGE_NOT_HELD;
	}
	bResult = NT_SUCCESS(status);
	NtClose(hToken);
	return bResult;
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
	BOOL cond = FALSE;
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

	} while (cond);

	if (ProcessList != NULL) {
		HeapFree(GetProcessHeap(), 0, ProcessList);
	}
	return bResult;
}

/*
* supNetworkConnectionEnable
*
* Purpose:
*
* Enable/Disable given network connection.
*
*/
HRESULT supNetworkConnectionEnable(
	_In_ LPTSTR szConnectionName,
	_In_ BOOL bEnable
	)
{
	HRESULT hResult = E_FAIL, hResultOp = E_FAIL;
	INetConnectionManager *pNetConnectionManager = NULL;
	IEnumNetConnection *pEnumNetConnection;
	ULONG ulCount = 0;
	BOOL bFound = FALSE;
	NETCON_PROPERTIES* pProps = NULL;
	INetConnection* pConn = NULL;

	hResult = CoInitialize(NULL);
	if (FAILED(hResult)) {
		return hResult;
	}

	hResult = CoCreateInstance(&CLSID_ConnectionManager, NULL,
		CLSCTX_LOCAL_SERVER | CLSCTX_NO_CODE_DOWNLOAD, &IID_INetConnectionManager,
		(LPVOID *)&pNetConnectionManager);

	if (SUCCEEDED(hResult)) {
		hResult = pNetConnectionManager->lpVtbl->EnumConnections(pNetConnectionManager, NCME_DEFAULT, &pEnumNetConnection);
		if (hResult == S_OK) {
			do {
				hResult = pEnumNetConnection->lpVtbl->Next(pEnumNetConnection, INET_CONNECTION_COUNT, &pConn, &ulCount);
				if (SUCCEEDED(hResult) && ulCount == INET_CONNECTION_COUNT)
				{
					hResult = pConn->lpVtbl->GetProperties(pConn, &pProps);
					if (hResult == S_OK)
					{
						if (_strcmpi(szConnectionName, pProps->pszwName) == 0) {
							bFound = TRUE;
							if (bEnable) {
								hResultOp = pConn->lpVtbl->Connect(pConn);
							}
							else {
								hResultOp = pConn->lpVtbl->Disconnect(pConn);
							}
							if (FAILED(hResultOp)) hResult = hResultOp;
						}
						CoTaskMemFree(pProps->pszwName);
						CoTaskMemFree(pProps->pszwDeviceName);
						CoTaskMemFree(pProps);
					}
					pConn->lpVtbl->Release(pConn);
					pConn = NULL;
				}
			} while (SUCCEEDED(hResult) && (ulCount == INET_CONNECTION_COUNT) && !bFound);
			pEnumNetConnection->lpVtbl->Release(pEnumNetConnection);
		}
		pNetConnectionManager->lpVtbl->Release(pNetConnectionManager);
	}
	CoUninitialize();

	return hResult;
}

/*
* supGetCommandLineParamA
*
* Purpose:
*
* Query token from command line.
*
* Return value: TRUE on success, FALSE otherwise
*
* Remark: ANSI variant
*
*/
BOOL supGetCommandLineParamA(
	IN	LPCSTR	CmdLine,
	IN	ULONG	ParamIndex,
	OUT	LPSTR	Buffer,
	IN	ULONG	BufferSize,
	OUT	PULONG	ParamLen
	)
{
	ULONG	c, plen = 0;
	TCHAR	divider;

	if (CmdLine == NULL)
		return FALSE;

	if (ParamLen != NULL)
		*ParamLen = 0;

	for (c = 0; c <= ParamIndex; c++) {
		plen = 0;

		while (*CmdLine == ' ')
			CmdLine++;

		switch (*CmdLine) {
		case 0:
			goto zero_term_exit;

		case '"':
			CmdLine++;
			divider = '"';
			break;

		default:
			divider = ' ';
		}

		while ((*CmdLine != '"') && (*CmdLine != divider) && (*CmdLine != 0)) {
			plen++;
			if (c == ParamIndex)
				if ((plen < BufferSize) && (Buffer != NULL)) {
					*Buffer = *CmdLine;
					Buffer++;
				}
			CmdLine++;
		}

		if (*CmdLine != 0)
			CmdLine++;
	}

zero_term_exit:

	if ((Buffer != NULL) && (BufferSize > 0))
		*Buffer = 0;

	if (ParamLen != NULL)
		*ParamLen = plen;

	if (plen < BufferSize)
		return TRUE;
	else
		return FALSE;
}


/*
* supGetCommandLineParamW
*
* Purpose:
*
* Query token from command line.
*
* Return value: TRUE on success, FALSE otherwise
*
* Remark: UNICODE variant
*
*/
BOOL supGetCommandLineParamW(
	IN	LPCWSTR	CmdLine,
	IN	ULONG	ParamIndex,
	OUT	LPWSTR	Buffer,
	IN	ULONG	BufferSize,
	OUT	PULONG	ParamLen
	)
{
	ULONG	c, plen = 0;
	TCHAR	divider;

	if (ParamLen != NULL)
		*ParamLen = 0;

	if (CmdLine == NULL) {
		if ((Buffer != NULL) && (BufferSize > 0))
			*Buffer = 0;
		return FALSE;
	}

	for (c = 0; c <= ParamIndex; c++) {
		plen = 0;

		while (*CmdLine == ' ')
			CmdLine++;

		switch (*CmdLine) {
		case 0:
			goto zero_term_exit;

		case '"':
			CmdLine++;
			divider = '"';
			break;

		default:
			divider = ' ';
		}

		while ((*CmdLine != '"') && (*CmdLine != divider) && (*CmdLine != 0)) {
			plen++;
			if (c == ParamIndex)
				if ((plen < BufferSize) && (Buffer != NULL)) {
					*Buffer = *CmdLine;
					Buffer++;
				}
			CmdLine++;
		}

		if (*CmdLine != 0)
			CmdLine++;
	}

zero_term_exit:

	if ((Buffer != NULL) && (BufferSize > 0))
		*Buffer = 0;

	if (ParamLen != NULL)
		*ParamLen = plen;

	if (plen < BufferSize)
		return TRUE;
	else
		return FALSE;
}
