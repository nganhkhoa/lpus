> If you came here for `MmNonPagedPoolStart`, `MmNonPagedPoolEnd`, you ended up at the right place.

`NonPagedPool` in Windows has two variables that defined the start and end of the section in kernel memory. Online blog posts and tutorials show an outdated version of these two variables.

Take a look at [this old post](https://web.archive.org/web/20061110120809/http://www.rootkit.com/newsread.php?newsid=153). `_DBGKD_GET_VERSION64 KdVersionBlock` was a very important structure into the debugger block of Windows. However, if you try to find this structure in Windows 10, you will hit `KdVersionBlock == 0` (Ouch!!!). But this structure provides offset into `MmNonPagedPool{Start,End}`, how can we get those?

Luckily, both `MmNonPagedPoolStart` and `MmNonPagedPoolEnd` in Windows XP, can be found by offseting from `ntoskrnl.exe`. Rekall team are very positive that their tools doesn't rely on profiles file like Volatility but use PDB provided by Windows to find these values.

In [Rekall source code](https://github.com/google/rekall/blob/c5d68e31705f4b5bd2581c1d951b7f6983f7089c/rekall-core/rekall/plugins/windows/pool.py#L87), the values of those variables are:

- Windows XP: `MmNonPagedPool{Start,End}`
- Windows 7 and maybe 8: `MiNonPagedPoolStartAligned`, `MiNonPagedPoolEnd`, and `MiNonPagedPoolBitMap`

In Windows 7, 8, another field was added to controll the allocation of `NonPagedPool`, which is also mentioned in [this paper about pool tag quick scanning](https://www.sciencedirect.com/science/article/pii/S1742287616000062).

However, from Windows 10, the whole game changed around when the global offset to those (similar) variables are gone. Instead Windows 10 introduced a new variable `MiState`. `MiState` offset is available and we can get those start/end variables by either:

- Windows 2015: `(_MI_SYSTEM_INFORMATION*)(MiState)->SystemNodeInformation.NonPagedPool{First,Last}Va`
- Windows 2016: `(_MI_SYSTEM_INFORMATION*)(MiState)->Hardware.SystemNodeInformation.NonPagedPool{First,Last}Va`

The `NonPagedBitMap` was still visible untill the May 2019 Update, here, take a look at these 2 consecutive update [`1809 Redstone 5 (October Update)`](https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/1809%20Redstone%205%20(October%20Update)/\_MI\_SYSTEM\_NODE\_INFORMATION) and [`1903 19H1 (May 2019 Update)`](https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/1903%2019H1%20(May%202019%20Update)/\_MI\_SYSTEM\_NODE\_INFORMATION).

Windows OS changes quite frequently right? Tell you more, I am using the Insider version of Windows in 2020, and guess what, I found out that they put another struct to point to those value. So now we need to go like this:

- Windows 2020 Insider preview: `*(_MI_SYSTEM_INFORMATION*)(MiState)->Hardware.SystemNodeNonPagedPool.NonPagedPool{First,Last}Va`

> If you go with low-level, then you only care about the offset and formula to get those variables but knowing the structure is well benefit.

Anyway, I create this project to help me with my thesis, following outdated structs online yields no result. Oh, yeah, a guy seems to be asking on [how to get `MmNonPagedPoolStart`](https://reverseengineering.stackexchange.com/q/6483) on `stackexchange`, too bad [the answer](https://reverseengineering.stackexchange.com/a/6487) is not so much helpful.

----

Global variables offset are parsed from the PDB file and can be queried by `nt!` in Windbg. In a kernel driver, we need to get the kernel base address (which is `nt!`). Kernel base address is the loaded address of `ntoskrnl.exe`. There is a shellcode to get the address [here](https://gist.github.com/Barakat/34e9924217ed81fd78c9c92d746ec9c6), using IDT table. But when I use the shellcode with the Windows Insider preview 2020, the address is wrong (it still a loaded PE though). Other ways to get the address are listed [here](https://m0uk4.gitbook.io/notebooks/mouka/windowsinternal/find-kernel-module-address-todo). And hereby I present another way to get the kernel base address.

A device driver can get a pointer to an `_EPROCESS` through the use of `PEPROCESS IoGetCurrentProcess`. And as we know, `_EPROCESS` has pointer to other `_EPROCESS` as a circular doubly linked list. If we dump them all out, we can notice a few things:

- The image name returned by calling `IoGetCurrentProcess` in `DriverEntry` is `System`
- The `_EPROCESS` before `System` is somehow empty

```cpp
// in DriverEntry
PVOID eprocess = (PVOID)IoGetCurrentProcess();

// somewhere after offsets are setup
DbgPrint("eprocess : 0x%p, [%15s]\n", eprocess, (char*)((ULONG64)eprocess + ImageBaseNameOffset));
for (int i = 0; i < 100; i++) {
  eprocess = (PVOID)(*(ULONG64*)((ULONG64)eprocess + ActiveProcessLinksOffset) - ActiveProcessLinksOffset);
  DbgPrint("eprocess : 0x%p, [%15s]\n", eprocess, (char*)((ULONG64)eprocess + ImageBaseOffset));
}

// sample output
eprocess : 0xFFFFF8037401F528, [               ]
eprocess : 0xFFFF840F5A0D9080, [         System]
eprocess : 0xFFFF840F5A28C040, [  Secure System]
eprocess : 0xFFFF840F5A2EF040, [       Registry]
eprocess : 0xFFFF840F622BF040, [       smss.exe]
eprocess : 0xFFFF840F6187D080, [       smss.exe]
eprocess : 0xFFFF840F6263D140, [      csrss.exe]
eprocess : 0xFFFF840F6277F0C0, [       smss.exe]
eprocess : 0xFFFF840F627C2080, [    wininit.exe]
eprocess : 0xFFFF840F64187140, [      csrss.exe]
eprocess : 0xFFFF840F641CD080, [   services.exe]
```

And if we debug and compare the address of that `Empty _EPROCESS+ActiveProcessLinksOffset` with `nt!PsActiveProcessHead`, it is just the same. And with the given offset parsed from the PDB file, we can get kernel base address.

```cpp
// In DriverEntry
PVOID eprocess = (PVOID)IoGetCurrentProcess();

// somwhere after offsets are setup
DbgPrint("eprocess               : 0x%p, [%15s]\n", eprocess, (char*)((ULONG64)eprocess + ImageBaseNameOffset));
PVOID processHead = (PVOID)(*(ULONG64*)((ULONG64)eprocess + ActiveProcessLinksOffset + BLinkOffset));
DbgPrint("PsActiveProcessHead    : 0x%p\n", processHead);
PVOID ntosbase = (PVOID)((ULONG64)processHead - ActiveHeadOffset);
DbgPrint("ntoskrnl.exe           : 0x%p\n", ntosbase);
```

From now we have successfully get the kernel base address to index into other global variables.

