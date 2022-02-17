#include "Reflective.h"
#include "Resource.h"

int main()
{
    DWORD PID;
    printf("PID : ");
    scanf("%d", &PID);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

    if (hProcess == NULL)
    {
        printf("OpenProcess Failed\n");
        printf("GetLastError : %d\n", GetLastError());
        return -1;
    }

    HMODULE hModule = Reflective(hProcess, testdll);
}