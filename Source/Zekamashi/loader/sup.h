/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2019
*
*  TITLE:       SUP.H
*
*  VERSION:     1.100
*
*  DATE:        04 Jan 2019
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
    _In_ BOOL	fEnable);

VOID supPurgeSystemCache(
    VOID);

PVOID supGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS InfoClass);

BOOL supProcessExist(
    _In_ LPWSTR lpProcessName);

BOOL supLoadDeviceDriver(
    VOID);

BOOL supRestartVBoxDrv(
    _Out_ PULONG lastErrorValue);
