/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2020
*
*  TITLE:       SUP.H
*
*  VERSION:     2.01
*
*  DATE:        02 Mar 2020
*
*  Common header file for the program support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

typedef NTSTATUS(NTAPI* PENUMOBJECTSCALLBACK)(POBJECT_DIRECTORY_INFORMATION Entry, PVOID CallbackParam);

typedef struct _OBJSCANPARAM {
    PWSTR Buffer;
    ULONG BufferSize;
} OBJSCANPARAM, * POBJSCANPARAM;

typedef struct _SUP_VERINFO_NUMBERS {
    DWORD VersionMS;
    DWORD VersionLS;
} SUP_VERINFO_NUMBERS, * PSUP_VERINFO_NUMBERS;

BOOLEAN supIsObjectExists(
    _In_ LPWSTR RootDirectory,
    _In_ LPWSTR ObjectName);

PVOID supHeapAlloc(
    _In_ SIZE_T Size);

BOOL supHeapFree(
    _In_ PVOID Memory);

BOOL supRegDeleteKeyRecursive(
    _In_ HKEY hKeyRoot,
    _In_ LPWSTR lpSubKey);

NTSTATUS supLoadDriver(
    _In_ LPCWSTR DriverName,
    _In_ LPCWSTR DriverPath,
    _In_ BOOLEAN UnloadPreviousInstance);

NTSTATUS supUnloadDriver(
    _In_ LPCWSTR DriverName,
    _In_ BOOLEAN fRemove);

NTSTATUS supOpenDriver(
    _In_ LPCWSTR DriverName,
    _Out_ PHANDLE DeviceHandle);

NTSTATUS supEnablePrivilege(
    _In_ DWORD Privilege,
    _In_ BOOL Enable);

VOID supPurgeSystemCache(
    VOID);

PVOID supGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS InfoClass);

BOOL supProcessExist(
    _In_ LPWSTR lpProcessName);

BOOL supGetCommandLineOption(
    _In_ LPCTSTR OptionName,
    _In_ BOOL IsParametric,
    _Inout_opt_ LPTSTR OptionValue,
    _In_ ULONG ValueSize);

BOOLEAN supQueryHVCIState(
    _Out_ PBOOLEAN pbHVCIEnabled,
    _Out_ PBOOLEAN pbHVCIStrictMode,
    _Out_ PBOOLEAN pbHVCIIUMEnabled);

DWORD supExpandEnvironmentStrings(
    _In_ LPCWSTR lpSrc,
    _Out_writes_to_opt_(nSize, return) LPWSTR lpDst,
    _In_ DWORD nSize);

void supResolveKernelImport(
    _In_ ULONG_PTR Image,
    _In_ ULONG_PTR KernelImage,
    _In_ ULONG_PTR KernelBase);

ULONG_PTR supGetProcAddress(
    _In_ ULONG_PTR KernelBase,
    _In_ ULONG_PTR KernelImage,
    _In_ LPCSTR FunctionName);

SIZE_T supWriteBufferToFile(
    _In_ PWSTR lpFileName,
    _In_ PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ BOOL Flush,
    _In_ BOOL Append,
    _Out_opt_ NTSTATUS* Result);

PBYTE supQueryResourceData(
    _In_ ULONG_PTR ResourceId,
    _In_ PVOID DllHandle,
    _In_ PULONG DataSize);

ULONG_PTR supGetNtOsBase(
    VOID);

BOOL supQueryObjectFromHandle(
    _In_ HANDLE hOject,
    _Out_ ULONG_PTR* Address);

ULONG_PTR supQueryMaximumUserModeAddress();

PVOID supFindPattern(
    _In_ CONST PBYTE Buffer,
    _In_ SIZE_T BufferSize,
    _In_ CONST PBYTE Pattern,
    _In_ SIZE_T PatternSize);

HANDLE supGetCurrentProcessToken(
    VOID);

BOOL supUserIsFullAdmin(
    VOID);

PSID supQueryTokenUserSid(
    _In_ HANDLE ProcessToken);

PVOID supGetTokenInfo(
    _In_ HANDLE TokenHandle,
    _In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
    _Out_opt_ PULONG ReturnLength);

BOOL supGetImageVersionInfo(
    _In_ PWSTR lpFileName,
    _In_ PSUP_VERINFO_NUMBERS VersionNumbers);
