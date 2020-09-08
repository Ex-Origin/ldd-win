
## ldd-win

A similar Linux ldd command for EXE files.

Use Windows Debug API to get dll information.

```
E:\>ldd main.exe
        0x00007ff7e7d70000    E:\main.exe
        0x00007ffc231c0000    C:\Windows\SYSTEM32\ntdll.dll
        0x00007ffc22580000    C:\Windows\System32\KERNEL32.DLL
        0x00007ffc20c00000    C:\Windows\System32\KERNELBASE.dll

E:\>ldd main2.exe
        0x00400000    E:\main2.exe
        0x77480000    C:\Windows\SYSTEM32\ntdll.dll
        0x75890000    C:\Windows\System32\KERNEL32.DLL
        0x770a0000    C:\Windows\System32\KERNELBASE.dll
        0x74da0000    C:\Windows\System32\OLEAUT32.dll
        0x74ea0000    C:\Windows\System32\msvcp_win.dll
        0x75260000    C:\Windows\System32\ucrtbase.dll
        0x767d0000    C:\Windows\System32\combase.dll
        0x75fe0000    C:\Windows\System32\RPCRT4.dll
        0x74c50000    C:\Windows\System32\SspiCli.dll
        0x74c40000    C:\Windows\System32\CRYPTBASE.dll
        0x77040000    C:\Windows\System32\bcryptPrimitives.dll
        0x74fa0000    C:\Windows\System32\sechost.dll
        0x74a30000    C:\Windows\SYSTEM32\VCRUNTIME140.dll
        0x72bf0000    C:\Windows\SYSTEM32\MSVCP140.dll
```

Email: 2462148389@qq.com

If you have any questions, please give a mail.
