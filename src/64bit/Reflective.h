#define once

#include <stdio.h>
#include <windows.h>

#define MZ 0x5A4D
#define PE 0x00004550

#define STRLEN(String, Length) \
do \
{ \
	Length = 0; \
	while (1) \
	{ \
		if (String[Length] == 0x00) \
			break; \
		Length++; \
	} \
} while (0)

// #define WCSTOMBS(mbstr, wcstr, count) \
// do \
// { \
// 	for (int i = 0; i < count; i++) \
// 	{ \
// 		*(BYTE *)(mbstr + i) = (BYTE)*(WORD *)((LPWSTR)wcstr + i); \
//         if ((BYTE)*(WORD *)((LPWSTR)wcstr + i) == 0x00) \
//             break; \
// 	} \
// } while (0)

typedef struct _BASE_RELOCATION_ENTRY
{
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

#ifndef _WINTERNL_
typedef VOID (NTAPI *PPS_POST_PROCESS_INIT_ROUTINE)(VOID);

typedef struct _UNICODE_STRING 
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS 
{
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY     InLoadOrderModuleList;
	LIST_ENTRY     InMemoryOrderModuleList;
	LIST_ENTRY     InInitializationOrderModuleList;
	PVOID          DllBase;
	PVOID          EntryPoint;
	ULONG          SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG          Flags;
	USHORT         ObsoleteLoadCount;
	USHORT         TlsIndex;
	LIST_ENTRY     HashLinks;
	ULONG          TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA
{
	DWORD      Length;
	BYTE       Initialized;
	PVOID      SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID      EntryInProgress;
	BYTE       ShutdownInProgress;
	PVOID      ShutdownThreadId
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB 
{
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA                 Ldr;
	PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	PVOID                         Reserved4[3];
	PVOID                         AtlThunkSListPtr;
	PVOID                         Reserved5;
	ULONG                         Reserved6;
	PVOID                         Reserved7;
	ULONG                         Reserved8;
	ULONG                         AtlThunkSListPtr32;
	PVOID                         Reserved9[45];
	BYTE                          Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE                          Reserved11[128];
	PVOID                         Reserved12[1];
	ULONG                         SessionId;
} PEB, *PPEB;
#endif