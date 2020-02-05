/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2020
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     2.00
*
*  DATE:        24 Jan 2020
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
#pragma warning(disable: 6320) // Exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER.

#if !defined UNICODE
#error ANSI build is not supported
#endif

#include <Windows.h>
#include <strsafe.h>
#include <ntstatus.h>
#include "ntdll/ntos.h"

#define _NTDEF_
#include <ntsecapi.h>
#undef _NTDEF_

#include "resource.h"
#include "minirtl/minirtl.h"
#include "minirtl/cmdline.h"
#include "hde/hde64.h"
#include "patterns.h"
#include "consts.h"
#include "sup.h"
#include "idrv/nal.h"
#include "victim.h"
#include "drvmap.h"

#define T_PRNTDEFAULT   "%s\r\n"

extern ULONG_PTR g_MaximumUserModeAddress;
