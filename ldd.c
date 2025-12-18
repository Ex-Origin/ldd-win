#include <Windows.h>
#include <winnt.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>
#include <psapi.h>
#include <tchar.h>
#include <shlwapi.h>
#include <strsafe.h>

#pragma comment(lib, "shlwapi.lib")   // PathFileExistsA, StrChrA, StrChrW
#pragma comment(lib, "user32.lib")    // wsprintfA, wsprintfW
#pragma comment(lib, "psapi.lib")     // GetModuleFileNameExA, GetMappedFileName

#define ASSERT(expression)                                                                                                                            \
    {                                                                                                                                                 \
        if (!(expression))                                                                                                                            \
        {                                                                                                                                             \
            fprintf(stderr, "\"" #expression "\" failed with error code %d in %s:%d (function: %s)\n", GetLastError(), __FILE__, __LINE__, __func__); \
            fflush(stderr);                                                                                                                           \
            ExitProcess(EXIT_FAILURE);                                                                                                                \
        }                                                                                                                                             \
    }

#define TRAP_INSTRUCT "\xcc"

// WoW64 specific exception codes (for 32-bit processes on 64-bit Windows)
#ifndef STATUS_WX86_BREAKPOINT
#define STATUS_WX86_BREAKPOINT 0x4000001F
#endif
#ifndef STATUS_WX86_SINGLE_STEP
#define STATUS_WX86_SINGLE_STEP 0x4000001E
#endif

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

int GetCharCountInStr(CHAR *str, char ch)
{
    int cnt = 0;
    while (*str) cnt += (int)(*str++ == ch);
    return cnt;
}

BOOL FileInDir(CHAR *dir, CHAR *file)
{
    WIN32_FIND_DATA structWFD;
    HANDLE hSrch;
    BOOL ret = FALSE;

    //ASSERT((hSrch = FindFirstFileA(dir, &structWFD)) != INVALID_HANDLE_VALUE);
    hSrch = FindFirstFileA(dir, &structWFD);
    if (hSrch == INVALID_HANDLE_VALUE) // if dir in PATH, but dir not exists now
    {
        if (GetLastError() == ERROR_PATH_NOT_FOUND)
        {
            return FALSE;
        }
        else
        {
            fprintf(stderr, "%d:%s:FindFirstFileA error, code: %d", __LINE__, __func__, GetLastError());
            exit(1);
        }
    }

    do
    {
        if (!strcmp(structWFD.cFileName, file)) 
        {
            ret = TRUE;
            break;
        }
    } while (FindNextFileA(hSrch, &structWFD));

    FindClose(hSrch);
    return ret;
}

#define MAX_FULL_PATH 32767
static BOOL searchInPath = FALSE;
static BOOL showAddresses = FALSE;
static int execNameArgIdx = -1;
static CHAR *copyToDirPathA = NULL;
static WCHAR *copyToDirPathW = NULL;
static BOOL ignoreExceptions = FALSE;

BOOL GetFileFullName(CHAR *name, CHAR *to, int toSize, int *resSize)
{
    DWORD n;
    
    if (PathFileExistsA(name))
    {
        if (!(n = GetFullPathNameA(name, toSize, to, 0)))
        {
            fprintf(stderr, "GetFullPathNameW error, code:%d", GetLastError());
            exit(1);
        }
    }
    else if (searchInPath)
    {
        // search in PATH

        CHAR envPathBuf[MAX_FULL_PATH + 3]; // +3 for adding "\*" for correct search
        int pathElemsCnt;
        memset(envPathBuf, 0, sizeof(envPathBuf));

        if (!(n = GetEnvironmentVariableA("PATH", envPathBuf, MAX_FULL_PATH)))
        {
            fprintf(stderr, "GetFullPathNameW error, code:%d", GetLastError());
            exit(1);
        }
        envPathBuf[n] = ';';
        envPathBuf[n+1] = '\0';
        pathElemsCnt = GetCharCountInStr(envPathBuf, ';');

        CHAR *curElem = envPathBuf;
        while (pathElemsCnt--) {
            CHAR *nextElem = strchr(curElem, ';'); // get next ';'
            char saveFirstChar = nextElem[1];
            char saveSecondChar = nextElem[2];

            // for correct searching
            nextElem[0] = '\\';
            nextElem[1] = '*';
            nextElem[2] = '\0';

            if (FileInDir(curElem, name))
            {
                nextElem[1] = '\0';
                n = snprintf(to, toSize, "%s%s", curElem, name);
                break;
            }

            nextElem[0] = ';';
            nextElem[1] = saveFirstChar;
            nextElem[2] = saveSecondChar;

            curElem = nextElem + 1;
        }

        if (pathElemsCnt == -1)
        {
            // name not founded
            return FALSE;
        }
    }
    else
    {
        return FALSE;
    }

    if (resSize)
    {
        *resSize = n;
    }

    return n < toSize;
}

BOOL DirectoryExists(CHAR *szPath)
{
  DWORD dwAttrib = GetFileAttributesA(szPath);

  return (dwAttrib != INVALID_FILE_ATTRIBUTES && 
         (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

void ParseCommandLine(int argc, char **argv)
{
    if (argc < 2)
    {
see_help:
        fprintf(stderr, "See help :-()");
        exit(1);
    }

    int i;
    for (i = 1; i < argc; i++)
    {
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) 
        {
            printf("Usage: %s [-p] [-a] [-c target-dir] FILE\n", argv[0]);
            printf("Note: use file name with \".exe\" and set in tail of cmdline\n");
            printf("    -p            if not found locally, then search in PATH\n");
            printf("    -a            show library addresses\n");
            printf("    -c            copy files to directory\n");
            printf("    -i            ignore exception from child process\n");
            printf("    -h, --help    show help\n");
            exit(0);
        }
        else if (!strcmp(argv[i], "-p"))
        {
            searchInPath = TRUE;
        }
        else if (!strcmp(argv[i], "-a"))
        {
            showAddresses = TRUE;
        }
        else if (!strcmp(argv[i], "-c"))
        {
            CHAR *s;
            int len;
            int k;
            if (i+1 >= argc)
            {
                fprintf(stderr, "-c requered value\n");
                exit(1);
            }

            s = argv[i+1];
            if (!DirectoryExists(s))
            {
                fprintf(stderr, "directory %s now exists\n", s);
                exit(1);
            }

            len = strlen(s);
            ASSERT((copyToDirPathA = (CHAR*)malloc(len+1)));
            ASSERT((copyToDirPathW = (WCHAR*)malloc((len+1) * sizeof(WCHAR))));
            
            for (k = 0; k < len + 1 /* with '\0' */; ++k)
            {
                copyToDirPathA[k] = s[k];
                copyToDirPathW[k] = (WCHAR)s[k];
            }
            i++;
        }
        else if (!strcmp(argv[i], "-i"))
        {
            ignoreExceptions = TRUE;
        }
        else
        {
            if (execNameArgIdx != -1)
            {
                goto see_help;
            }
            else
            {
                execNameArgIdx = i;
            }
        }
    }
}

WCHAR *StrCharFromEndW(WCHAR *str, WCHAR ch)
{
    WCHAR *ptr = str;
    WCHAR *savematch;

    do
    {
        savematch = ptr;
        ptr = StrChrW(ptr+1, ch);
    } while (ptr);
    
    return *savematch == ch ? savematch : NULL;
}

CHAR *StrCharFromEndA(CHAR *str, CHAR ch)
{
    CHAR *ptr = str;
    CHAR *savematch;

    do
    {
        savematch = ptr;
        ptr = StrChrA(ptr+1, ch);
    } while (ptr);

    return *savematch == ch ? savematch : NULL;
}

BOOL CopyToDirA(CHAR *fileFullPath, CHAR *toDir)
{
    CHAR *fileName; 
    CHAR *resPathTo;
    CHAR *ptr;
    int fileLen;
    int toDirLen;
    BOOL ret;
    
    ASSERT((fileName = StrCharFromEndA(fileFullPath, '\\')) != NULL);
    // if (!(fileName = StrCharFromEndA(fileFullPath, '\\')))
    // {
    //     printf("strcharA err\t");
    //     return FALSE;
    // }
    fileName++;

    fileLen = lstrlenA(fileName);
    toDirLen = lstrlenA(toDir);
    ASSERT((resPathTo = (CHAR*)malloc(fileLen + toDirLen + 2)) != NULL);

    wsprintfA(resPathTo, "%s\\%s", toDir, fileName);
    ret = CopyFileA(fileFullPath, resPathTo, FALSE);
    free(resPathTo);
    return ret;
}

BOOL CopyToDirW(WCHAR *fileFullPath, WCHAR *toDir)
{
    WCHAR *fileName; 
    WCHAR *resPathTo;
    WCHAR *ptr;
    int fileLen;
    int toDirLen;
    BOOL ret;

    ASSERT((fileName = StrCharFromEndW(fileFullPath, '\\')) != NULL);
    // if (!(fileName = StrCharFromEndW(fileFullPath, (WCHAR)'\\')))
    // {
    //     printf("strcharW err\t");
    //     return FALSE;
    // }
    fileName++;

    fileLen = lstrlenW(fileName);
    toDirLen = lstrlenW(toDir);
    ASSERT((resPathTo = (WCHAR*)malloc((fileLen + toDirLen + 2) * sizeof(WCHAR))) != NULL);

    wsprintfW(resPathTo, L"%s\\%s", toDir, fileName);
    ret = CopyFileW(fileFullPath, resPathTo, FALSE);
    free(resPathTo);
    return ret;
}

int main(int argc, char **argv)
{
    CHAR buf[0x200], OutputBuf[0x1000];
    CHAR execName[8192];
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

    ParseCommandLine(argc, argv);

    ASSERT(GetFileFullName(argv[execNameArgIdx], execName, sizeof(execName), 0));

    ASSERT((FileHandle = CreateFileA(execName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE);
    ASSERT(ReadFile(FileHandle, &ImageDosHeader, sizeof(ImageDosHeader), &Dresult, NULL) != 0);
    ASSERT(SetFilePointer(FileHandle, ImageDosHeader.e_lfanew, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER);
    ASSERT(ReadFile(FileHandle, &ImageNtHeaders, sizeof(ImageNtHeaders), &Dresult, NULL) != 0);

    EntryPoint = ImageNtHeaders.OptionalHeader.AddressOfEntryPoint;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    ASSERT(CreateProcessA(NULL, execName, NULL, NULL, FALSE, DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED, NULL, NULL, &si, &pi) == TRUE);
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
            if (!ignoreExceptions)
            {
                switch (DebugEv.u.Exception.ExceptionRecord.ExceptionCode)
                {
                case EXCEPTION_ACCESS_VIOLATION:
                    printf("EXCEPTION_ACCESS_VIOLATION:    The thread tried to read from or write to a virtual address for which it does not have the appropriate access.\n\n");
                    exit(EXIT_SUCCESS);
                    break;

                case EXCEPTION_BREAKPOINT:
                    // Normal x86/x64 breakpoint - continue
                    break;

                case STATUS_WX86_BREAKPOINT:
                    // WoW64 breakpoint (32-bit process on 64-bit Windows) - continue
                    break;

                case STATUS_WX86_SINGLE_STEP:
                    // WoW64 single step (32-bit process on 64-bit Windows) - continue
                    break;

                case EXCEPTION_DATATYPE_MISALIGNMENT:
                    printf("EXCEPTION_DATATYPE_MISALIGNMENT:    The thread tried to read or write data that is misaligned on hardware that does not provide alignment. "
                        "For example, 16-bit values must be aligned on 2-byte boundaries; 32-bit values on 4-byte boundaries, and so on.\n\n");
                    exit(EXIT_SUCCESS);
                    break;

                case EXCEPTION_SINGLE_STEP:
                    // Normal single step - continue
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
                    // For unknown exceptions, don't exit - just continue debugging
                    // This allows the tool to continue enumerating DLLs
                    fprintf(stderr, "Unknown Event [0x%x] - continuing...\n", DebugEv.u.Exception.ExceptionRecord.ExceptionCode);
                    break;
                }
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
                    if (copyToDirPathW)
                    {
                        if (CopyToDirW((WCHAR*)OutputBuf, copyToDirPathW))
                            printf("copy success\t");
                        else
                            printf("copy   error\t");
                    }

                    if (showAddresses)
                    {
                        wprintf(L"        0x%p    %s\n", lpBaseOfDll, (unsigned short *)OutputBuf);
                    }
                    else
                    {
                        wprintf(L"%s\n", (unsigned short *)OutputBuf);
                    }
                }
                else
                {
                    if (copyToDirPathA)
                    {
                        if (CopyToDirA(OutputBuf, copyToDirPathA))
                            printf("copy success\t");
                        else
                            printf("copy   error\t");
                    }

                    if (showAddresses)
                    {
                        printf("        0x%p    %s\n", lpBaseOfDll, (unsigned short *)OutputBuf);
                    }
                    else
                    {
                        printf("%s\n", (unsigned short *)OutputBuf);
                    }
                }
            }
            else if (GetModuleFileNameExA(pi.hProcess, (HMODULE)lpBaseOfDll, OutputBuf, sizeof(OutputBuf)) != 0)
            {
                if (copyToDirPathA)
                {
                    if (CopyToDirA(OutputBuf, copyToDirPathA))
                        printf("copy success\t");
                    else
                        printf("copy   error\t");
                }

                if (showAddresses)
                {
                    printf("        0x%p    %s\n", lpBaseOfDll, OutputBuf);
                }
                else
                {
                    printf("%s\n", OutputBuf);
                }
            }
            else if (GetFileNameFromHandle(DebugEv.u.LoadDll.hFile, (TCHAR *)OutputBuf) != 0)
            {
                if (copyToDirPathA)
                {
                    if (CopyToDirA(OutputBuf, copyToDirPathA))
                        printf("copy success\t");
                    else
                        printf("copy   error\t");
                }

                if (showAddresses)
                {
                    wprintf(L"        0x%p    %hs\n", lpBaseOfDll, (TCHAR *)OutputBuf);
                }
                else
                {
                    wprintf(L"%hs\n", (TCHAR *)OutputBuf);
                }
            }
        }
        else if (DebugEv.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && GetFileNameFromHandle(DebugEv.u.CreateProcessInfo.hFile, (TCHAR *)OutputBuf) != 0)
        {
    #if 0
            if (showAddresses)
            {
                wprintf(L"        0x%p    %hs\n", DebugEv.u.CreateProcessInfo.lpBaseOfImage, (TCHAR *)OutputBuf);
            }
            else
            {
                wprintf(L"%hs\n", (TCHAR *)OutputBuf);
            }
    #endif
        }
        ASSERT(ContinueDebugEvent(DebugEv.dwProcessId, DebugEv.dwThreadId, DBG_CONTINUE) != 0);
    }
    TerminateProcess(pi.hProcess, 0);

    if (copyToDirPathW) free(copyToDirPathW);
    if (copyToDirPathA) free(copyToDirPathA);

    return 0;
}
