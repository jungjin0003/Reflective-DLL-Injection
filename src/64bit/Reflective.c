#include "Reflective.h"

int main()
{
    
}

HMODULE Reflective(HANDLE hProcess, BYTE* MemoryStream)
{
    /*printf("[+] File Name : %s\n", DllName);

    HANDLE hFile = CreateFileA(DllName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD Size = GetFileSize(hFile, NULL);
    printf("[*] File Size : %d Byte\n", Size);

    BYTE* Buffer = malloc(Size);
    ReadFile(hFile, Buffer, Size, &Size, NULL);
    printf("[+] File Opening!\n");*/

    ULONGLONG RowImageBase = MemoryStream;
    IMAGE_DOS_HEADER* DOS = MemoryStream;

    if (DOS->e_magic != MZ)
    {
        printf("[-] This memory stream is not executable file!\n");
        return NULL;
    }

    IMAGE_NT_HEADERS64* NT = RowImageBase + DOS->e_lfanew;

    if (NT->Signature != PE)
    {
        printf("[-] This memory stream is not PE format\n");
        return NULL;
    }

    ULONGLONG ImageBase;
    ULONGLONG OriginImageBase = NT->OptionalHeader.ImageBase;

    if (!(ImageBase = VirtualAlloc(NT->OptionalHeader.ImageBase, NT->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
    {
        ImageBase = VirtualAlloc(NULL, NT->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    if (ImageBase == NULL)
    {
        printf("[-] VirtualAlloc failed!!\n");
        return NULL;
    }
    printf("[*] ImageBase : 0x%p\n", ImageBase);

    memcpy(ImageBase, DOS, NT->OptionalHeader.SizeOfHeaders);
    printf("[+] PE headers writing by %d Byte\n", NT->OptionalHeader.SizeOfHeaders);

    IMAGE_SECTION_HEADER (*SECTION)[1] = (ULONGLONG)NT + sizeof(IMAGE_NT_HEADERS64);
    printf("[*] First section : 0x%p\n", SECTION);

    for (int i = 0; i < NT->FileHeader.NumberOfSections; i++)
    {
        printf("[+] Section name : %s\n", SECTION[i]->Name);
        memcpy(ImageBase + SECTION[i]->VirtualAddress, RowImageBase + SECTION[i]->PointerToRawData, SECTION[i]->SizeOfRawData);
        printf("[+] Section mapping OK..!\n");
    }

    IMAGE_IMPORT_DESCRIPTOR (*IMPORT)[1] = ImageBase + NT->OptionalHeader.DataDirectory[1].VirtualAddress;
    printf("[*] IAT Recovery\n");

    for (int i = 0;; i++)
    {
        if (IMPORT[i]->OriginalFirstThunk == NULL)
            break;

        PSTR LibName = ImageBase + IMPORT[i]->Name;
        printf("[+] Library name : %s\n", LibName);

        HMODULE hModule;
        if (!(hModule = GetModuleHandleA(LibName)))
        {
            hModule = LoadLibraryA(LibName);
        }

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
            BASE_RELOCATION_ENTRY (*Type)[1] = (ULONGLONG)BASE_RELOCATION + 8;
            for (int i = 0; i < (BASE_RELOCATION->SizeOfBlock - 8) / 2; i++)
            {
                if ((*Type[i]).Offset != NULL)
                {
                    ULONGLONG *HardCodingAddress = ImageBase + BASE_RELOCATION->VirtualAddress + (*Type[i]).Offset;
                    ULONGLONG HardCodingData = *HardCodingAddress;

                    /*if (ReadProcessMemory(pi.hProcess, HardCodingAddress, &HardCodingData, 8, NULL) == NULL)
                    {
                        printf("[-] Reloc Read Failed!\n");
                        continue;
                    }*/

                    printf("[+] 0x%p : 0x%p -> ", HardCodingAddress, HardCodingData);

                    HardCodingData -= (ULONGLONG)OriginImageBase;
                    HardCodingData += (ULONGLONG)ImageBase;

                    printf("0x%p\n", HardCodingData);

                    *HardCodingAddress = HardCodingData;
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
    HANDLE hThread = CreateThread2(NULL, NULL, EntryPoint, CREATE_SUSPENDED, &TID, 3, ImageBase, DLL_PROCESS_ATTACH, NULL);

    if (hThread == NULL)
    {
        printf("[-] Failed create thread!\n");
        VirtualFree(ImageBase, MEM_RELEASE, 0);
        return NULL;
    }

    ResumeThread(hThread);

    printf("[+] Thread handle : 0x%x\n", hThread);
    printf("[+] ThreadId : %d\n", TID);

    return (HMODULE)ImageBase;
}