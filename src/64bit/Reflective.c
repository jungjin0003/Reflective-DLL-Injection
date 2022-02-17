#include "Reflective.h"
#include "Resource.h"

void Failed(LPCSTR Message);
IMAGE_SECTION_HEADER *FindSection(PVOID RVA, IMAGE_SECTION_HEADER (*SECTION)[1], DWORD NumberOfSections);

HMODULE Reflective(HANDLE hProcess, BYTE *MemoryStream)
{
    SIZE_T NumberOfBytesWritten;
    WINBOOL bSuccess;
    IMAGE_SECTION_HEADER *Section;

    ULONGLONG RawImageBase = MemoryStream;
    IMAGE_DOS_HEADER *DOS = MemoryStream;

    if (DOS->e_magic != MZ)
    {
        printf("[-] This memory stream is not executable file!\n");
        return NULL;
    }

    IMAGE_NT_HEADERS64 *NT = RawImageBase + DOS->e_lfanew;

    if (NT->Signature != PE)
    {
        printf("[-] This memory stream is not PE format\n");
        return NULL;
    }

    ULONGLONG ImageBase;
    ULONGLONG OriginImageBase = NT->OptionalHeader.ImageBase;

    if (!(ImageBase = VirtualAllocEx(hProcess, NT->OptionalHeader.ImageBase, NT->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
    {
        ImageBase = VirtualAllocEx(hProcess, NULL, NT->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    if (ImageBase == NULL)
    {
        Failed("VirtualAlloc failed!!");
        return NULL;
    }
    printf("[*] ImageBase : 0x%p\n", ImageBase);

    // memcpy(ImageBase, DOS, NT->OptionalHeader.SizeOfHeaders);
    bSuccess = WriteProcessMemory(hProcess, ImageBase, DOS, NT->OptionalHeader.SizeOfHeaders, &NumberOfBytesWritten);
    if (!bSuccess)
    {
        Failed("DOS header write failed!");
        VirtualFreeEx(hProcess, ImageBase, 0, MEM_RELEASE);
        return NULL;
    }

    printf("[+] PE headers writing by %d Byte\n", NumberOfBytesWritten);

    IMAGE_SECTION_HEADER (*SECTION)[1] = (ULONGLONG)NT + sizeof(IMAGE_NT_HEADERS64);
    printf("[*] First section : 0x%p\n", SECTION);

    for (int i = 0; i < NT->FileHeader.NumberOfSections; i++)
    {
        printf("[+] Section name : %s\n", SECTION[i]->Name);
        bSuccess = WriteProcessMemory(hProcess, ImageBase + SECTION[i]->VirtualAddress, RawImageBase + SECTION[i]->PointerToRawData, SECTION[i]->SizeOfRawData, &NumberOfBytesWritten);
        if (!bSuccess)
        {
            Failed("Section write failed!");
            VirtualFreeEx(hProcess, ImageBase, 0, MEM_RELEASE);
            return NULL;
        }
        printf("[+] Section mapping OK..!\n");
    }

    Section = FindSection(NT->OptionalHeader.DataDirectory[1].VirtualAddress, SECTION, NT->FileHeader.NumberOfSections);

    IMAGE_IMPORT_DESCRIPTOR (*IMPORT)[1] = VA2WA(RawImageBase + NT->OptionalHeader.DataDirectory[1].VirtualAddress, Section->VirtualAddress, Section->PointerToRawData);
    printf("[*] IAT Recovery\n");

    HMODULE hModule = GetRemoteModuleHandleA(hProcess, "kernelbase.dll");

    if (hModule == NULL)
    {
        Failed("Get kernelbase.dll HMODULE failed!");
        VirtualFreeEx(hProcess, ImageBase, 0, MEM_RELEASE);
        return NULL;
    }

    PVOID RemoteLoadLibraryA = GetRemoteProcAddress(hProcess, hModule, "LoadLibraryA");

    if (RemoteLoadLibraryA == NULL)
    {
        Failed("Get LoadLibraryA address failed!");
        VirtualFreeEx(hProcess, ImageBase, 0, MEM_RELEASE);
        return NULL;
    }

    for (int i = 0;; i++)
    {
        if (IMPORT[i]->OriginalFirstThunk == NULL)
            break;

        Section = FindSection(IMPORT[i]->Name, SECTION, NT->FileHeader.NumberOfSections);

        LPCSTR LibName = VA2WA(RawImageBase + IMPORT[i]->Name, Section->VirtualAddress, Section->PointerToRawData);
        printf("[+] Library name : %s\n", LibName);

        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, RemoteLoadLibraryA, ImageBase + IMPORT[i]->Name, 0, NULL);

        if (hThread == NULL)
        {
            Failed("DLL Injection failed!");
            VirtualFreeEx(hProcess, ImageBase, 0, MEM_RELEASE);
            return NULL;
        }

        WaitForSingleObject(hThread, INFINITE);

        HMODULE hModule = GetRemoteModuleHandleA(hProcess, LibName);

        if (hModule == NULL)
        {
            Failed("Get HMODULE failed!");
            VirtualFreeEx(hProcess, ImageBase, 0, MEM_RELEASE);
            return NULL;
        }

        printf("[+] HMODULE : 0x%p\n", hModule);

        for (int j = 0;; j++)
        {
            Section = FindSection(IMPORT[i]->OriginalFirstThunk + j * 8, SECTION, NT->FileHeader.NumberOfSections);
            IMAGE_THUNK_DATA64 *THUNK = VA2WA(RawImageBase + IMPORT[i]->OriginalFirstThunk + j * 8, Section->VirtualAddress, Section->PointerToRawData);

            if (THUNK->u1.AddressOfData == NULL)
                break;

            if (THUNK->u1.Ordinal >= 0x80000000)
                *(ULONGLONG *)(ImageBase + IMPORT[i]->FirstThunk + j * 8) = GetProcAddress(hModule, MAKEINTRESOURCEA(THUNK->u1.Ordinal));
            else
            {
                Section = FindSection(THUNK->u1.AddressOfData, SECTION, NT->FileHeader.NumberOfSections);
                IMAGE_IMPORT_BY_NAME *IMPORT_NAME = VA2WA(RawImageBase + THUNK->u1.AddressOfData, Section->VirtualAddress, Section->PointerToRawData);
                printf("[+] Function name : %s\n", IMPORT_NAME->Name);
                PVOID Function = GetRemoteProcAddress(hProcess, hModule, IMPORT_NAME->Name);
                WriteProcessMemory(hProcess, ImageBase + IMPORT[i]->FirstThunk + j * 8, &Function, 8, NULL);
            }
        }
    }

    if (ImageBase != NT->OptionalHeader.ImageBase)
    {
        printf("[*] Relocation hardcoding data\n");
        IMAGE_BASE_RELOCATION *BASE_RELOCATION = NULL;
        for (int i = 0; i < NT->FileHeader.NumberOfSections; i++)
        {
            if (NT->OptionalHeader.DataDirectory[5].VirtualAddress == SECTION[i]->VirtualAddress)
            {
                BASE_RELOCATION = RawImageBase + SECTION[i]->PointerToRawData;
                break;
            }
        }

        DWORD SIZE_RELOCATION = NT->OptionalHeader.DataDirectory[5].Size;

        if (BASE_RELOCATION == NULL | SIZE_RELOCATION == 0)
        {
            Failed("This DLL is not supported Relocation!");
            VirtualFree(ImageBase, MEM_RELEASE, 0);
            return NULL;
        }

        DWORD SIZE = 0;

        while (SIZE != SIZE_RELOCATION)
        {
            BASE_RELOCATION_ENTRY (*Type)[1] = (ULONGLONG)BASE_RELOCATION + 8;
            for (int i = 0; i < (BASE_RELOCATION->SizeOfBlock - 8) / 2; i++)
            {
                if ((*Type[i]).Offset != NULL)
                {
                    ULONGLONG *HardCodingAddress = ImageBase + BASE_RELOCATION->VirtualAddress + (*Type[i]).Offset;
                    ULONGLONG HardCodingData;

                    if (ReadProcessMemory(hProcess, HardCodingAddress, &HardCodingData, 8, NULL) == FALSE)
                    {
                        Failed("Reloc read failed!");
                        VirtualFreeEx(hProcess, ImageBase, 0, MEM_RELEASE);
                        return NULL;
                    }

                    printf("[+] 0x%p : 0x%p -> ", HardCodingAddress, HardCodingData);

                    HardCodingData -= (ULONGLONG)OriginImageBase;
                    HardCodingData += (ULONGLONG)ImageBase;

                    printf("0x%p\n", HardCodingData);

                    if (WriteProcessMemory(hProcess, HardCodingAddress, &HardCodingData, 8, NULL) == FALSE)
                    {
                        Failed("Reloc write failed!");
                        VirtualFreeEx(hProcess, ImageBase, 0, MEM_RELEASE);
                        return NULL;
                    }
                }
            }

            SIZE += BASE_RELOCATION->SizeOfBlock;
            BASE_RELOCATION = (ULONGLONG)BASE_RELOCATION + BASE_RELOCATION->SizeOfBlock;
        }
    }

    PVOID EntryPoint = ImageBase + NT->OptionalHeader.AddressOfEntryPoint;

    printf("[*] EntryPoint : 0x%p\n", EntryPoint);

    printf("[*] Create New Thread!\n");

    BYTE CallDllMainShellCode[] = { 0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x89, 0xC8, 0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00, 0x49, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x48, 0x01, 0xC8, 0xFF, 0xD0, 0xC9, 0xC3 };

    PVOID CallDllMain = VirtualAllocEx(hProcess, NULL, sizeof(CallDllMainShellCode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (CallDllMain == NULL)
    {
        Failed("Failed allocate shellcode space!");
        VirtualFreeEx(hProcess, ImageBase, 0, MEM_RELEASE);
        return NULL;
    }

    *(ULONGLONG *)(CallDllMainShellCode + 13) = ImageBase;

    if (WriteProcessMemory(hProcess, CallDllMain, CallDllMainShellCode, sizeof(CallDllMainShellCode), NULL) == FALSE)
    {
        Failed("CallDllMain ShellCode write failed!");
        VirtualFreeEx(hProcess, ImageBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, CallDllMain, 0, MEM_RELEASE);
        return NULL;
    }

    DWORD TID;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, CallDllMain, NT->OptionalHeader.AddressOfEntryPoint, 0, &TID); //= CreateThread2(NULL, NULL, EntryPoint, CREATE_SUSPENDED, &TID, 3, ImageBase, DLL_PROCESS_ATTACH, NULL);

    if (hThread == NULL)
    {
        Failed("Failed create thread!");
        VirtualFreeEx(hProcess, ImageBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, CallDllMain, 0, MEM_RELEASE);
        return NULL;
    }

    printf("[+] Thread handle : 0x%x\n", hThread);
    printf("[+] ThreadId : %d\n", TID);

    WaitForSingleObject(hThread, INFINITE);

    DWORD ExitCode;

    GetExitCodeThread(hThread, &ExitCode);

    if (ExitCode)
        printf("[+] Reflective DLL Injection success!!\n");
    else
    {
        printf("[+] DllMain return value is FALSE!\n");
        Failed("Reflective DLL Injection failed");
        VirtualFreeEx(hProcess, ImageBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, CallDllMain, 0, MEM_RELEASE);
        return NULL;
    }

    return (HMODULE)ImageBase;
}

void Failed(LPCSTR Message)
{
    printf("[-] %s\n", Message);
    DWORD ErrorCode = GetLastError();
    printf("[+] GetLastError : %d\n", ErrorCode);
    LPSTR ErrorMessage;
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER, NULL, ErrorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), &ErrorMessage, 0, NULL);
    printf("[+] ErrorMessage : %s\n", ErrorMessage);
}

IMAGE_SECTION_HEADER *FindSection(PVOID RVA, IMAGE_SECTION_HEADER (*SECTION)[1], DWORD NumberOfSections)
{
    for (int i = 0; i < NumberOfSections; i++)
    {
        if (SECTION[i]->VirtualAddress <= RVA && RVA <= SECTION[i]->VirtualAddress + SECTION[i]->Misc.VirtualSize)
        {
            return SECTION[i];
        }
    }

    return NULL;
}