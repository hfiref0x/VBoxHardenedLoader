/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2015
*
*  TITLE:       DSEFIX.H
*
*  VERSION:     1.20
*
*  DATE:        14 Mar 2015
*
*  Common header file for the DSEFix support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

HANDLE dsfLoadVulnerableDriver(
	_In_ LPWSTR lpDriverFileName
	);

BOOL dsfControlDSE(
	HANDLE hDevice,
	ULONG_PTR g_CiAddress,
	PVOID scBuffer
	);

BOOL dsfStartDriver(
	_In_ LPWSTR lpDriverName,
	_Inout_opt_	PHANDLE lphDevice
	);

BOOL dsfStopDriver(
	_In_ LPWSTR lpDriverName
	);

LONG dsfQueryCiOptions(
	PULONG_PTR pKernelBase,
	PVOID MappedKernel
	);

LONG dsfQueryCiEnabled(
	PULONG_PTR pKernelBase,
	PVOID MappedKernel,
	DWORD SizeOfImage
	);

#define VBoxDrvSvc		L"VBoxDrv"
