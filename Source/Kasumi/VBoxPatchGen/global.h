/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2019
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     1.20
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
//disable nonmeaningful warnings.
#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union

#if !defined UNICODE
#error ANSI build is not supported
#endif

#if defined (_MSC_VER)
#if (_MSC_VER >= 1900) //VS15, 17 etc
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libucrt.lib")
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif
#endif

#include <Windows.h>
#include <ntstatus.h>
#include "ntos.h"
#include "minirtl\minirtl.h"
#include "minirtl\cmdline.h"
#include "cui.h"
#include "patterns.h"

typedef struct _BINARY_PATCH_BLOCK {
    ULONG	VirtualOffset;
    UCHAR	DataLength;
    UCHAR	Data[1];
} BINARY_PATCH_BLOCK, *PBINARY_PATCH_BLOCK;

typedef struct _BINARY_PATCH_BLOCK_INTERNAL {
    ULONG	VirtualOffset;
    UCHAR	DataLength;
    UCHAR	Data[32];
} BINARY_PATCH_BLOCK_INTERNAL, *PBINARY_PATCH_BLOCK_INTERNAL;
