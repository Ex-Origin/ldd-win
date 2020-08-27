#include <Windows.h>
#include <winnt.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>

#define ASSERT(expression)                                                                                                                            \
    {                                                                                                                                                 \
        if (!(expression))                                                                                                                            \
        {                                                                                                                                             \
            fprintf(stderr, "\"" #expression "\" failed with error code %d in %s:%d (function: %s)\n", GetLastError(), __FILE__, __LINE__, __func__); \
            ExitProcess(EXIT_FAILURE);                                                                                                                \
        }                                                                                                                                             \
    }

#define TRAP_INSTRUCT "\xcc"

int main(int argc, char** argv)
{
    CHAR buf[0x200], OutputBuf[0x1000];
    IMAGE_DOS_HEADER ImageDosHeader;
    IMAGE_NT_HEADERS ImageNtHeaders;
    HANDLE StdoutHandle, StderrHandle;
    HANDLE FileHandle;
    size_t EntryPoint, ImageBaseAddress, PebAddress, PEB_LDR_DATA, InMemoryOrderModuleList, address, next, head, result;
    NTSTATUS(__stdcall * NtQueryInformationProcessHook)
        (HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    PROCESS_BASIC_INFORMATION Information;
    DEBUG_EVENT DebugEv;
    CHAR* ImageFile;

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    int i;

    StdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    StderrHandle = GetStdHandle(STD_ERROR_HANDLE);
    if (argc < 2)
    {
        WriteFile(StderrHandle, "Usage: ldd FILE\n", 16, (LPDWORD)&result, NULL);
        ExitProcess(EXIT_FAILURE);
    }

    result = 0;
    ASSERT((FileHandle = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE);
    ASSERT(ReadFile(FileHandle, &ImageDosHeader, sizeof(ImageDosHeader), (LPDWORD)&result, NULL) != 0);
    ASSERT(SetFilePointer(FileHandle, ImageDosHeader.e_lfanew, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER);
    result = 0;
    ASSERT(ReadFile(FileHandle, &ImageNtHeaders, sizeof(ImageNtHeaders), (LPDWORD)&result, NULL) != 0);

    EntryPoint = ImageNtHeaders.OptionalHeader.AddressOfEntryPoint;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    ASSERT(CreateProcessA(NULL, argv[1], NULL, NULL, FALSE, DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED, NULL, NULL, &si, &pi) == TRUE);
    ASSERT(DebugSetProcessKillOnExit(TRUE) != 0);
    NtQueryInformationProcessHook = (NTSTATUS(__stdcall*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueryInformationProcess");
    ASSERT(NtQueryInformationProcessHook != NULL);
    ASSERT(NtQueryInformationProcessHook(pi.hProcess, ProcessBasicInformation, &Information, sizeof(Information), NULL) == 0);
    PebAddress = (size_t)Information.PebBaseAddress;

    ASSERT(ReadProcessMemory(pi.hProcess, (CHAR*)PebAddress + (sizeof(PVOID) * 2), &ImageBaseAddress, sizeof(PVOID), &result) != 0);
    ASSERT(WriteProcessMemory(pi.hProcess, (CHAR*)ImageBaseAddress + EntryPoint, TRAP_INSTRUCT, sizeof(TRAP_INSTRUCT), &result) != 0);
    ASSERT(result == sizeof(TRAP_INSTRUCT));
    ResumeThread(pi.hThread);

    while (TRUE)
    {
        WaitForDebugEvent(&DebugEv, INFINITE);
        // Process the debugging event code.
        if (DebugEv.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
        {
            ASSERT(DebugEv.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT);

            if ((size_t)DebugEv.u.Exception.ExceptionRecord.ExceptionAddress == ImageBaseAddress + EntryPoint)
                ;
            break;
        }
        ASSERT(ContinueDebugEvent(DebugEv.dwProcessId, DebugEv.dwThreadId, DBG_CONTINUE) != 0);
    }

    ASSERT(ReadProcessMemory(pi.hProcess, (CHAR*)PebAddress + (sizeof(PVOID) * 3), &PEB_LDR_DATA, sizeof(PVOID), &result) != 0);
    ASSERT(result == sizeof(PVOID));

    ASSERT(ReadProcessMemory(pi.hProcess, (CHAR*)PEB_LDR_DATA + (sizeof(PVOID) * 4), &InMemoryOrderModuleList, sizeof(PVOID), &result) != 0);
    ASSERT(result == sizeof(PVOID));

    ASSERT(ReadProcessMemory(pi.hProcess, (CHAR*)InMemoryOrderModuleList, buf, 0x50, &result) != 0);
    ASSERT(result == 0x50);

    head = InMemoryOrderModuleList;

    next = *(size_t*)(buf + 0);
    ImageFile = *(char**)(buf + 0x40);
    address = *(size_t*)(buf + 0x20);

    for (i = 0; TRUE; i++)
    {
        ASSERT(ReadProcessMemory(pi.hProcess, ImageFile + i * 2, OutputBuf + i, 1, &result) != 0);
        ASSERT(result == 1);

        if (OutputBuf[i] == '\0')
            break;
    }
    printf("        0x%016llx    %s\n", address, OutputBuf);

    while (next != head)
    {
        ASSERT(ReadProcessMemory(pi.hProcess, (CHAR*)next, buf, 0x50, &result) != 0);
        ASSERT(result == 0x50);

        next = *(size_t*)(buf + 0);
        ImageFile = *(char**)(buf + 0x40);
        address = *(size_t*)(buf + 0x20);

        if (ImageFile == 0 || address == 0)
        {
            break;
        }

        for (i = 0; TRUE; i++)
        {
            ASSERT(ReadProcessMemory(pi.hProcess, ImageFile + i * 2, OutputBuf + i, 1, &result) != 0);
            ASSERT(result == 1);

            if (OutputBuf[i] == '\0')
                break;
        }
        printf("        0x%016llx    %s\n", address, OutputBuf);
    }
    TerminateProcess(pi.hProcess, 0);

    return 0;
}
