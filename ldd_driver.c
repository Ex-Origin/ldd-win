#include <Windows.h>
#include <stdio.h>

#define ASSERT(expression)                                                                                                                            \
    {                                                                                                                                                 \
        if (!(expression))                                                                                                                            \
        {                                                                                                                                             \
            fprintf(stderr, "\"" #expression "\" failed with error code %d in %s:%d (function: %s)\n", GetLastError(), __FILE__, __LINE__, __func__); \
            ExitProcess(EXIT_FAILURE);                                                                                                                \
        }                                                                                                                                             \
    }

int StrNCat(char str[], char *append, int strLength)
{
    int length, i;

    length = strlen(str);
    for (i = length; i < (strLength - 1) && *append; i++)
    {
        str[i] = *append;
        append++;
    }

    if (i < (strLength - 1))
        return 0;
    else
        return 1;
}

int main(int argc, char **argv)
{
    HANDLE StdoutHandle, StderrHandle, FileHandle;
    IMAGE_DOS_HEADER ImageDosHeader;
    IMAGE_NT_HEADERS ImageNtHeaders;
    DWORD result;

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    char buf[0x1000];

    StdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    StderrHandle = GetStdHandle(STD_ERROR_HANDLE);
    if (argc < 2)
    {
        WriteFile(StderrHandle, "Usage: ldd FILE\n", 16, &result, NULL);
        ExitProcess(EXIT_FAILURE);
    }

    ASSERT((FileHandle = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE);
    ASSERT(ReadFile(FileHandle, &ImageDosHeader, sizeof(ImageDosHeader), &result, NULL) != 0);
    ASSERT(SetFilePointer(FileHandle, ImageDosHeader.e_lfanew, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER);
    ASSERT(ReadFile(FileHandle, &ImageNtHeaders, sizeof(ImageNtHeaders), &result, NULL) != 0);

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    ZeroMemory(buf, sizeof(buf));

    if (ImageNtHeaders.FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
    {
        StrNCat(buf, "ldd86.exe ", sizeof(buf));
        ASSERT(StrNCat(buf, argv[1], sizeof(buf)) == 0);
        ASSERT(CreateProcessA(NULL, buf, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi) == TRUE);
    }
    else if (ImageNtHeaders.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
    {
        StrNCat(buf, "ldd64.exe ", sizeof(buf));
        ASSERT(StrNCat(buf, argv[1], sizeof(buf)) == 0);
        ASSERT(CreateProcessA(NULL, buf, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi) == TRUE);
    }
    else
    {
        fprintf(stderr, "Unrecognized file\n");
        ExitProcess(EXIT_FAILURE);
    }

    ASSERT(WaitForSingleObject(pi.hProcess, INFINITE) != WAIT_FAILED);

    return 0;
}