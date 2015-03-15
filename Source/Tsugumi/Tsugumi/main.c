/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2015
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.00
*
*  DATE:        14 Mar 2015
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include <ntddk.h>

DRIVER_INITIALIZE	DriverEntry;
DRIVER_UNLOAD		TsmiUnload;
NTSTATUS			TsmiHandleMemWrite(_In_ PVOID SrcAddress, _In_ PVOID DestAddress, _In_ ULONG Size, _Inout_ PULONG BytesWritten);
VOID				TsmiPsImageHandler(_In_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo);

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, TsmiHandleMemWrite)
#pragma alloc_text(PAGE, TsmiPsImageHandler)
#pragma alloc_text(PAGE, TsmiUnload)

typedef struct _BINARY_PATCH_BLOCK {
	ULONG	VirtualOffset;
	UCHAR	DataLength;
	UCHAR	Data[1];
} BINARY_PATCH_BLOCK, *PBINARY_PATCH_BLOCK;

#define TSUGUMI_TAG			'imsT'
#define BLOCK_DATA_OFFSET	(ULONG_PTR)(&((PBINARY_PATCH_BLOCK)0)->Data)

static PKEY_VALUE_PARTIAL_INFORMATION	PatchChains = NULL;

/*
* TsmiHandleMemWrite
*
* Purpose:
*
* Patch VBoxDD.dll in memory.
*
*/
NTSTATUS TsmiHandleMemWrite(
	_In_ PVOID SrcAddress,
	_In_ PVOID DestAddress,
	_In_ ULONG Size,
	_Inout_ PULONG BytesWritten
	)
{
	PMDL		mdl;
	NTSTATUS	status = STATUS_SUCCESS;

	PAGED_CODE();

	if (ARGUMENT_PRESENT(BytesWritten))
		*BytesWritten = 0;

	mdl = IoAllocateMdl(DestAddress, Size, FALSE, FALSE, NULL);
	if (mdl == NULL) {
#ifdef _DEBUG
		DbgPrint("[TSMI] Failed to create MDL at write");
#endif
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	__try {

		if (DestAddress >= MmSystemRangeStart)
			if (!MmIsAddressValid(DestAddress)) {
#ifdef _DEBUG
				DbgPrint("[TSMI] Invalid address");
#endif
				return STATUS_ACCESS_VIOLATION;
			}

		MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
#ifdef _DEBUG
		DbgPrint("[TSMI] Write -> MmGetSystemAddressForMdlSafe");
#endif
		DestAddress = MmGetSystemAddressForMdlSafe(mdl, HighPagePriority);
		if (DestAddress != NULL) {
			status = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
#ifdef _DEBUG
			DbgPrint("[TSMI] Mapped at %p for write, protect status = %lx", DestAddress, status);
#endif
			memcpy(DestAddress, SrcAddress, Size);
			MmUnmapLockedPages(DestAddress, mdl);
			MmUnlockPages(mdl);
			if (ARGUMENT_PRESENT(BytesWritten))
				*BytesWritten = Size;
		}
		else {
			status = STATUS_ACCESS_VIOLATION;
#ifdef _DEBUG
			DbgPrint("[TSMI] MmGetSystemAddressForMdlSafe failed at write");
#endif
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = STATUS_ACCESS_VIOLATION;
#ifdef _DEBUG
		DbgPrint("[TSMI] MmProbeAndLockPages failed at write DestAddress = %p", DestAddress);
#endif
	}

	IoFreeMdl(mdl);
	return status;
}

/*
* TsmiPsImageHandler
*
* Purpose:
*
* Notify to catch VBoxDD.dll loading.
*
*/
VOID TsmiPsImageHandler(
	_In_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,                // pid into which image is being mapped
	_In_ PIMAGE_INFO ImageInfo
	)
{
	static const WCHAR		DDname[] = L"VBoxDD.dll";
	ULONG					c, l = 0;
	PBINARY_PATCH_BLOCK		Chains;

	PAGED_CODE();

	//
	// Validate input parameters.
	//
	if (
		(FullImageName == NULL) ||
		(ImageInfo == NULL) ||
		(PsGetCurrentProcessId() != ProcessId)
		)
	{
		return;
	}

	if (
		(FullImageName->Buffer == NULL) ||
		(FullImageName->Length == 0)
		)
	{
		return;
	}

	//
	// Validate patch data
	//
	if (PatchChains == NULL) {
		return;
	}

	//
	// Extract dll name
	//
	for (c = 0; c < (ULONG)FullImageName->Length / sizeof(WCHAR); c++)
		if (FullImageName->Buffer[c] == '\\')
			l = c + 1;

	//
	// Compare dll if this is our target and patch it on true.
	//
	if (_wcsnicmp(&FullImageName->Buffer[l], DDname, wcslen(DDname)) == 0) {

		l = 0;
		Chains = (PBINARY_PATCH_BLOCK)&PatchChains->Data[0];

		//
		// Apply each patch from chains.
		//
		while (l + BLOCK_DATA_OFFSET < PatchChains->DataLength) {

			if (Chains->DataLength != 0) {

				TsmiHandleMemWrite(
					Chains->Data,
					(PVOID)((ULONG_PTR)ImageInfo->ImageBase + Chains->VirtualOffset), 
					Chains->DataLength, &c
					);
			}
			
			l += BLOCK_DATA_OFFSET + Chains->DataLength;
			Chains = (PBINARY_PATCH_BLOCK)((ULONG_PTR)Chains + BLOCK_DATA_OFFSET + 
				Chains->DataLength);
		}
		DbgPrint("[TSMI] VBoxDD patched");
	}
}

/*
* TsmiUnload
*
* Purpose:
*
* Driver unload procedure.
*
*/
VOID TsmiUnload(
	_In_  struct _DRIVER_OBJECT *DriverObject
	)
{
	PAGED_CODE();

	DbgPrint("[TSMI] Unload, DrvObj = %p", DriverObject);

	//
	// Free chains and remove notify.
	//
	if (PatchChains != NULL) {
		ExFreePoolWithTag(PatchChains, TSUGUMI_TAG);
	}
	PsRemoveLoadImageNotifyRoutine(TsmiPsImageHandler);
}


/*
* DriverEntry
*
* Purpose:
*
* Driver entry point.
*
*/
NTSTATUS DriverEntry(
	_In_  struct _DRIVER_OBJECT *DriverObject,
	_In_  PUNICODE_STRING RegistryPath
	)
{
	KEY_VALUE_PARTIAL_INFORMATION	keyinfo;
	NTSTATUS						status;
	HANDLE							sKey, pKey;
	OBJECT_ATTRIBUTES				kattr;
	UNICODE_STRING					s;
	ULONG							bytesIO = 0, ChainsLength;

	DbgPrint("[TSMI] Loaded, system range start is %p", MmSystemRangeStart);

	//
	// Validate input parameters.
	//
	if (RegistryPath == NULL) {
		return STATUS_INVALID_PARAMETER;
	}
	if (RegistryPath->Buffer == NULL) {
		return STATUS_INVALID_PARAMETER;
	}
	
	//
	// Open driver scm entry key.
	//
	InitializeObjectAttributes(&kattr, RegistryPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwOpenKey(&sKey, KEY_READ, &kattr);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	//
	// Open parameters key.
	//
	RtlInitUnicodeString(&s, L"Parameters");
	InitializeObjectAttributes(&kattr, &s, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, sKey, NULL);
	status = ZwOpenKey(&pKey, KEY_READ, &kattr);
	ZwClose(sKey);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	//
	// Query patch data size.
	//
	RtlInitUnicodeString(&s, L"PatchData");
	status = ZwQueryValueKey(pKey, &s, KeyValuePartialInformation, &keyinfo, sizeof(KEY_VALUE_PARTIAL_INFORMATION), &bytesIO);
	if ((status != STATUS_SUCCESS) && (status != STATUS_BUFFER_TOO_SMALL) && (status != STATUS_BUFFER_OVERFLOW)) {
		ZwClose(pKey);
		return status;
	}

	//
	// Correct patch chains if needed.
	//
	if (bytesIO >= sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 1024) {
		bytesIO = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 1024;
	}

	//
	//  Allocate patch chains.
	//
	ChainsLength = bytesIO;
	PatchChains = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTagPriority(PagedPool, 
		ChainsLength, TSUGUMI_TAG, NormalPoolPriority);
	
	if (PatchChains == NULL) {
		ZwClose(pKey);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlSecureZeroMemory(PatchChains, ChainsLength);

	//
	// Read chains to allocated buffer.
	//
	status = ZwQueryValueKey(pKey, &s, KeyValuePartialInformation, PatchChains, ChainsLength, &bytesIO);
	ZwClose(pKey);
	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(PatchChains, TSUGUMI_TAG);
		return status;
	}

	//
	// Set image loading notify routine.
	//
	status = PsSetLoadImageNotifyRoutine(TsmiPsImageHandler);
	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(PatchChains, TSUGUMI_TAG);
		return status;
	}

	DriverObject->DriverUnload = &TsmiUnload;

	return STATUS_SUCCESS;
}
