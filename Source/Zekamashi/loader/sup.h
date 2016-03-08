/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2016
*
*  TITLE:       SUP.H
*
*  VERSION:     1.50
*
*  DATE:        04 Mar 2016
*
*  Common header file for the program support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

BOOL supEnablePrivilege(
	_In_ DWORD	PrivilegeName,
	_In_ BOOL	fEnable
	);

VOID supPurgeSystemCache(
	VOID
	);

PVOID supGetSystemInfo(
	_In_ SYSTEM_INFORMATION_CLASS InfoClass
	);

BOOL supProcessExist(
	_In_ LPWSTR lpProcessName
	);
