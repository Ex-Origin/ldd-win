#include <Windows.h>
#include <winnt.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>
#include <psapi.h>
#include <tchar.h>
#include <strsafe.h>

#define ASSERT(expression)                                                                                                                            \
    {                                                                                                                                                 \
        if (!(expression))                                                                                                                            \
        {                                                                                                                                             \
            fprintf(stderr, "\"" #expression "\" failed with error code %d in %s:%d (function: %s)\n", GetLastError(), __FILE__, __LINE__, __func__); \
            ExitProcess(EXIT_FAILURE);                                                                                                                \
        }                                                                                                                                             \
    }

#define TRAP_INSTRUCT "\xcc"

BOOL GetFileNameFromHandle(HANDLE hFile, TCHAR *pszFilename)
{
    BOOL bSuccess = FALSE;
    HANDLE hFileMap;
    // Get the file size.
    DWORD dwFileSizeHi = 0;
    DWORD dwFileSizeLo = GetFileSize(hFile, &dwFileSizeHi);
    if (dwFileSizeLo == 0 && dwFileSizeHi == 0)
    {
        _tprintf(TEXT("Cannot map a file with a length of zero.\n"));
        return FALSE;
    }
    // Create a file mapping object.
    hFileMap = CreateFileMapping(hFile,
                                 NULL,
                                 PAGE_READONLY,
                                 0,
                                 1,
                                 NULL);
    if (hFileMap)
    {
        // Create a file mapping to get the file name.
        void *pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);
        if (pMem)
        {
            if (GetMappedFileName(GetCurrentProcess(),
                                  pMem,
                                  pszFilename,
                                  MAX_PATH))
            {
                // Translate path with device name to drive letters.
                TCHAR szTemp[0x1000];
                szTemp[0] = '\0';
                if (GetLogicalDriveStrings(0x1000 - 1, szTemp))
                {
                    TCHAR szName[MAX_PATH];
                    TCHAR szDrive[3] = TEXT(" :");
                    BOOL bFound = FALSE;
                    TCHAR *p = szTemp;
                    do
                    {
                        // Copy the drive letter to the template string
                        *szDrive = *p;
                        // Look up each device name
                        if (QueryDosDevice(szDrive, szName, MAX_PATH))
                        {
                            size_t uNameLen = _tcslen(szName);
                            if (uNameLen < MAX_PATH)
                            {
                                bFound = _tcsnicmp(pszFilename, szName, uNameLen) == 0;
                                if (bFound && *(pszFilename + uNameLen) == _T('\\'))
                                {
                                    // Reconstruct pszFilename using szTempFile
                                    // Replace device path with DOS path
                                    TCHAR szTempFile[MAX_PATH];
                                    StringCchPrintf(szTempFile,
                                                    MAX_PATH,
                                                    TEXT("%s%s"),
                                                    szDrive,
                                                    pszFilename + uNameLen);
                                    StringCchCopyN(pszFilename, MAX_PATH + 1, szTempFile, _tcslen(szTempFile));
                                }
                            }
                        }
                        // Go to the next NULL character.
                        while (*p++)
                            ;
                    } while (!bFound && *p); // end of string
                }
            }
            bSuccess = TRUE;
            UnmapViewOfFile(pMem);
        }
        CloseHandle(hFileMap);
    }
    return TRUE;
}

int main(int argc, char **argv)
{
    CHAR buf[0x200], OutputBuf[0x1000];
    IMAGE_DOS_HEADER ImageDosHeader;
    IMAGE_NT_HEADERS ImageNtHeaders;
    HANDLE StdoutHandle, StderrHandle;
    HANDLE FileHandle;
    DWORD Dresult;
    size_t result, EntryPoint, ImageBaseAddress, PebAddress, PEB_LDR_DATA, InMemoryOrderModuleList, address, next, head;
    NTSTATUS(__stdcall * NtQueryInformationProcessHook)
    (HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    PROCESS_BASIC_INFORMATION Information;
    DEBUG_EVENT DebugEv;
    CHAR *ImageFile;
    LPVOID lpBaseOfDll, lpImageName;
    size_t dwAddrImageName = 0;

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    int i;

    StdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    StderrHandle = GetStdHandle(STD_ERROR_HANDLE);
    if (argc < 2)
    {
        WriteFile(StderrHandle, "Usage: ldd FILE\n", 16, &Dresult, NULL);
        ExitProcess(EXIT_FAILURE);
    }

    ASSERT((FileHandle = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE);
    ASSERT(ReadFile(FileHandle, &ImageDosHeader, sizeof(ImageDosHeader), &Dresult, NULL) != 0);
    ASSERT(SetFilePointer(FileHandle, ImageDosHeader.e_lfanew, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER);
    ASSERT(ReadFile(FileHandle, &ImageNtHeaders, sizeof(ImageNtHeaders), &Dresult, NULL) != 0);

    EntryPoint = ImageNtHeaders.OptionalHeader.AddressOfEntryPoint;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    ASSERT(CreateProcessA(NULL, argv[1], NULL, NULL, FALSE, DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED, NULL, NULL, &si, &pi) == TRUE);
    ASSERT(DebugSetProcessKillOnExit(TRUE) != 0);
    NtQueryInformationProcessHook = (NTSTATUS(__stdcall *)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueryInformationProcess");
    ASSERT(NtQueryInformationProcessHook != NULL);
    ASSERT(NtQueryInformationProcessHook(pi.hProcess, ProcessBasicInformation, &Information, sizeof(Information), NULL) == 0);
    PebAddress = (size_t)Information.PebBaseAddress;

    ASSERT(ReadProcessMemory(pi.hProcess, (CHAR *)PebAddress + (sizeof(PVOID) * 2), &ImageBaseAddress, sizeof(PVOID), &result) != 0);
    ASSERT(WriteProcessMemory(pi.hProcess, (CHAR *)ImageBaseAddress + EntryPoint, TRAP_INSTRUCT, sizeof(TRAP_INSTRUCT), &result) != 0);
    ASSERT(result == sizeof(TRAP_INSTRUCT));
    ResumeThread(pi.hThread);

    while (TRUE)
    {
        WaitForDebugEvent(&DebugEv, INFINITE);
        // Process the debugging event code.
        if (DebugEv.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
        {
            switch (DebugEv.u.Exception.ExceptionRecord.ExceptionCode)
            {
            case EXCEPTION_ACCESS_VIOLATION:
                printf("EXCEPTION_ACCESS_VIOLATION:    The thread tried to read from or write to a virtual address for which it does not have the appropriate access.\n\n");
                exit(EXIT_SUCCESS);
                break;

            case EXCEPTION_BREAKPOINT:

                break;

            case EXCEPTION_DATATYPE_MISALIGNMENT:
                printf("EXCEPTION_DATATYPE_MISALIGNMENT:    The thread tried to read or write data that is misaligned on hardware that does not provide alignment. "
                       "For example, 16-bit values must be aligned on 2-byte boundaries; 32-bit values on 4-byte boundaries, and so on.\n\n");
                exit(EXIT_SUCCESS);
                break;

            case EXCEPTION_SINGLE_STEP:

                break;

            case DBG_CONTROL_C:
                ASSERT(TerminateProcess(pi.hProcess, 2) != 0);
                exit(EXIT_SUCCESS);
                break;

            case EXCEPTION_FLT_INVALID_OPERATION:
                printf("EXCEPTION_FLT_INVALID_OPERATION:    This exception represents any floating-point exception not included in this list.\n\n");
                exit(EXIT_SUCCESS);
                break;

            case EXCEPTION_FLT_STACK_CHECK:
                printf("EXCEPTION_FLT_STACK_CHECK:    The stack overflowed or underflowed as the result of a floating-point operation.\n\n");
                exit(EXIT_SUCCESS);
                break;

            case EXCEPTION_ILLEGAL_INSTRUCTION:
                printf("EXCEPTION_ILLEGAL_INSTRUCTION:    The thread tried to execute an invalid instruction.\n\n");
                exit(EXIT_SUCCESS);
                break;

            case EXCEPTION_IN_PAGE_ERROR:
                printf("EXCEPTION_IN_PAGE_ERROR:    The thread tried to access a page that was not present, and the system was unable to load the page."
                       " For example, this exception might occur if a network connection is lost while running a program over the network.\n\n");
                exit(EXIT_SUCCESS);
                break;

            case EXCEPTION_STACK_OVERFLOW:
                printf("EXCEPTION_STACK_OVERFLOW:    The thread used up its stack.\n\n");
                exit(EXIT_SUCCESS);
                break;

            default:
                printf("Unknow Event!\n\n");
                exit(EXIT_FAILURE);
                break;
            }

            if ((size_t)DebugEv.u.Exception.ExceptionRecord.ExceptionAddress == ImageBaseAddress + EntryPoint)
                break;
        }
        else if (DebugEv.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT)
        {
            lpBaseOfDll = DebugEv.u.LoadDll.lpBaseOfDll;
            lpImageName = DebugEv.u.LoadDll.lpImageName;
            ReadProcessMemory(pi.hProcess, lpImageName, &dwAddrImageName, sizeof(dwAddrImageName), &result);
            ZeroMemory(OutputBuf, sizeof(OutputBuf));
            if (result == sizeof(dwAddrImageName) && ReadProcessMemory(pi.hProcess, (LPCVOID)dwAddrImageName, OutputBuf, sizeof(OutputBuf), &result) != 0)
            {
                if (DebugEv.u.LoadDll.fUnicode)
                {
                    wprintf(L"        0x%p    %s\n", lpBaseOfDll, (unsigned short *)OutputBuf);
                }
                else
                {
                    printf("        0x%p    %s\n", lpBaseOfDll, OutputBuf);
                }
            }
            else if (GetModuleFileNameExA(pi.hProcess, (HMODULE)lpBaseOfDll, OutputBuf, sizeof(OutputBuf)) != 0)
            {
                printf("        0x%p    %s\n", lpBaseOfDll, OutputBuf);
            }
            else if (GetFileNameFromHandle(DebugEv.u.LoadDll.hFile, (TCHAR *)OutputBuf) != 0)
            {
                wprintf(L"        0x%p    %hs\n", lpBaseOfDll, (TCHAR *)OutputBuf);
            }
        }
        else if (DebugEv.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && GetFileNameFromHandle(DebugEv.u.CreateProcessInfo.hFile, (TCHAR *)OutputBuf) != 0)
        {
            wprintf(L"        0x%p    %hs\n", DebugEv.u.CreateProcessInfo.lpBaseOfImage, (TCHAR *)OutputBuf);
        }
        ASSERT(ContinueDebugEvent(DebugEv.dwProcessId, DebugEv.dwThreadId, DBG_CONTINUE) != 0);
    }
    TerminateProcess(pi.hProcess, 0);

    return 0;
}
