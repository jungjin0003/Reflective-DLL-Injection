#include "Reflective.h"

__declspec(naked) void CallDllMain(HINSTANCE hinstDLL);

int main()
{
    CallDllMain(NULL);
}

HMODULE Reflective(HANDLE hProcess, BYTE *MemoryStream)
{
    /*printf("[+] File Name : %s\n", DllName);

    HANDLE hFile = CreateFileA(DllName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD Size = GetFileSize(hFile, NULL);
    printf("[*] File Size : %d Byte\n", Size);

    BYTE* Buffer = malloc(Size);
    ReadFile(hFile, Buffer, Size, &Size, NULL);
    printf("[+] File Opening!\n");*/

    SIZE_T NumberOfBytesWritten;
    WINBOOL bSuccess;

    ULONGLONG RowImageBase = MemoryStream;
    IMAGE_DOS_HEADER *DOS = MemoryStream;

    if (DOS->e_magic != MZ)
    {
        printf("[-] This memory stream is not executable file!\n");
        return NULL;
    }

    IMAGE_NT_HEADERS64 *NT = RowImageBase + DOS->e_lfanew;

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
        printf("[-] VirtualAlloc failed!!\n");
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
        bSuccess = WriteProcessMemory(hProcess, ImageBase + SECTION[i]->VirtualAddress, RowImageBase + SECTION[i]->PointerToRawData, SECTION[i]->SizeOfRawData, &NumberOfBytesWritten);
        if (!bSuccess)
        {
            Failed("Section write failed!");
            VirtualFreeEx(hProcess, ImageBase, 0, MEM_RELEASE);
            return NULL;
        }
        printf("[+] Section mapping OK..!\n");
    }

    IMAGE_IMPORT_DESCRIPTOR (*IMPORT)[1] = ImageBase + NT->OptionalHeader.DataDirectory[1].VirtualAddress;
    printf("[*] IAT Recovery\n");

    PVOID SharedMemoryAddress = VirtualAllocEx(hProcess, NULL, 0, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (SharedMemoryAddress == NULL)
    {
        Failed("Shared memory allocate failed!");
        VirtualFreeEx(hProcess, ImageBase, 0, MEM_RELEASE);
        return NULL;
    }

    HMODULE (__stdcall *pGetModuleHandleA)(LPCSTR);

    for (int i = 0;; i++)
    {
        if (IMPORT[i]->OriginalFirstThunk == NULL)
            break;

        PSTR LibName = ImageBase + IMPORT[i]->Name;
        printf("[+] Library name : %s\n", LibName);

        bSuccess = WriteProcessMemory(hProcess, SharedMemoryAddress, LibName, strlen(LibName) + 1, NULL);
        if (!bSuccess)
        {
            printf("Write library name failed!");
            VirtualFreeEx(hProcess, ImageBase, 0, MEM_RELEASE);
            return NULL;
        }

        

        HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, GetModuleHandleA, SharedMemoryAddress, NULL, NULL);

        // HMODULE hModule;
        // if (!(hModule = GetModuleHandleA(LibName)))
        // {
        //     hModule = LoadLibraryA(LibName);
        // }

        for (int j = 0;; j++)
        {
            IMAGE_THUNK_DATA64 *THUNK = ImageBase + IMPORT[i]->OriginalFirstThunk + j * 8;

            if (THUNK->u1.AddressOfData == NULL)
                break;

            if (THUNK->u1.Ordinal > 0x80000000)
                *(ULONGLONG *)(ImageBase + IMPORT[i]->FirstThunk + j * 8) = GetProcAddress(hModule, MAKEINTRESOURCEA(THUNK->u1.Ordinal));
            else
            {
                IMAGE_IMPORT_BY_NAME *IMPORT_NAME = ImageBase + THUNK->u1.AddressOfData;
                printf("[+] Function name : %s\n", IMPORT_NAME->Name);
                *(ULONGLONG *)(ImageBase + IMPORT[i]->FirstThunk + j * 8) = GetProcAddress(hModule, IMPORT_NAME->Name);
            }
        }
    }

    if (ImageBase != NT->OptionalHeader.ImageBase)
    {
        IMAGE_BASE_RELOCATION *BASE_RELOCATION = NULL;
        for (int i = 0; i < NT->FileHeader.NumberOfSections; i++)
        {
            if (NT->OptionalHeader.DataDirectory[5].VirtualAddress == SECTION[i]->VirtualAddress)
            {
                BASE_RELOCATION = RowImageBase + SECTION[i]->PointerToRawData;
                break;
            }
        }

        DWORD SIZE_RELOCATION = NT->OptionalHeader.DataDirectory[5].Size;

        if (BASE_RELOCATION == NULL | SIZE_RELOCATION == 0)
        {
            printf("[-] This DLL is not supported Relocation!\n");
            VirtualFree(ImageBase, MEM_RELEASE, 0);
            return NULL;
        }

        DWORD SIZE = 0;

        while (SIZE != SIZE_RELOCATION)
        {
            BASE_RELOCATION_ENTRY(*Type)
            [1] = (ULONGLONG)BASE_RELOCATION + 8;
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

    DWORD TID;
    HANDLE hThread; //= CreateThread2(NULL, NULL, EntryPoint, CREATE_SUSPENDED, &TID, 3, ImageBase, DLL_PROCESS_ATTACH, NULL);

    if (hThread == NULL)
    {
        printf("[-] Failed create thread!\n");
        VirtualFreeEx(hProcess, ImageBase, 0, MEM_RELEASE);
        return NULL;
    }

    ResumeThread(hThread);

    printf("[+] Thread handle : 0x%x\n", hThread);
    printf("[+] ThreadId : %d\n", TID);

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

__declspec(naked) void CallDllMain(HINSTANCE hinstDLL)
{
    __asm__ __volatile__ (
        "push rbp\n\t"
        "mov rbp, rsp\n\t"
        "sub rsp, 0x20\n\t"
        "mov rdx, 0x1\n\t"
        "mov r8, 0x0\n\t"

        "leave\n\t"
        "ret\n\t"
    );
}

__declspec(naked) void *SearchFunction(int Key)
{
    __asm__ __volatile__ (
        "push rbp\n\t"
        "mov rbp, rsp\n\t"
        "sub rsp, 0x20\n\t"
        "mov qword ptr ds:[rbp+0x10], rcx\n\t" // Argument 1 save
        "mov rax, gs:[0x60]\n\t"               // Get PEB
        "mov rax, qword ptr ds:[rax+0x30]\n\t" // Get PEB_LDR_DATA
        "mov qword ptr ds:[rsp+0x18], rax\n\t" // Save address
        ""
    );
}