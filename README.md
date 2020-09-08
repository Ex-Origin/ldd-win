
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
        0x77070000    C:\Windows\SysWOW64\ntdll.dll
        0x74FD0000    C:\Windows\SysWOW64\KERNEL32.DLL
        0x76E60000    C:\Windows\SysWOW64\KERNELBASE.dll
        0x763A0000    C:\Windows\SysWOW64\OLEAUT32.dll
        0x74AF0000    C:\Windows\SysWOW64\msvcp_win.dll
        0x749D0000    C:\Windows\SysWOW64\ucrtbase.dll
        0x74B90000    C:\Windows\SysWOW64\combase.dll
        0x75E40000    C:\Windows\SysWOW64\RPCRT4.dll
        0x74840000    C:\Windows\SysWOW64\SspiCli.dll
        0x74830000    C:\Windows\SysWOW64\CRYPTBASE.dll
        0x75D60000    C:\Windows\SysWOW64\bcryptPrimitives.dll
        0x75AD0000    C:\Windows\SysWOW64\sechost.dll
        0x723D0000    C:\Windows\SysWOW64\MSVCP140.dll
        0x746C0000    C:\Windows\SysWOW64\vcruntime140.dll
```

Email: 2462148389@qq.com

If you have any questions, please give a mail.
