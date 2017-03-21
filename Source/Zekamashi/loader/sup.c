/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       SUP.C
*
*  VERSION:     1.81
*
*  DATE:        20 Mar 2017
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

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
		Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)Size);
		if (Buffer != NULL) {
			status = NtQuerySystemInformation(InfoClass, Buffer, Size, &memIO);
		}
		else {
			return NULL;
		}
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			HeapFree(GetProcessHeap(), 0, Buffer);
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
		HeapFree(GetProcessHeap(), 0, Buffer);
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

	HeapFree(GetProcessHeap(), 0, ProcessList);
	return bResult;
}

/*
* supLoadDeviceDriver
*
* Purpose:
*
* Load tsugumi.sys from current directory.
*
*/
BOOL supLoadDeviceDriver(
    VOID
)
{
    BOOL        bResult = FALSE, bCond = FALSE;
    SC_HANDLE   schSCManager = NULL;
    DWORD       cch;
    TCHAR       szFile[MAX_PATH * 2], szLog[MAX_PATH * 3];

    do {

        schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (schSCManager == NULL)
            break;

        RtlSecureZeroMemory(szFile, sizeof(szFile));
        cch = GetCurrentDirectory(MAX_PATH, szFile);
        if ((cch != 0) && (cch < MAX_PATH)) {
            _strcat(szFile, TEXT("\\"));
            _strcat(szFile, TSUGUMI_DRV_NAME);    

            _strcpy(szLog, TEXT("Ldr: Loading Tsugumi Monitor -> "));
            _strcat(szLog, szFile);
            cuiPrintText(g_ConOut, szLog, g_ConsoleOutput, TRUE);

            scmInstallDriver(schSCManager, TSUGUMI_DISP_NAME, szFile);
            bResult = scmStartDriver(schSCManager, TSUGUMI_DISP_NAME);
        }

    } while (bCond);

    if (schSCManager != NULL)
        CloseServiceHandle(schSCManager);

    return bResult;
}
