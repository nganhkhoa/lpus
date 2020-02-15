> If you came here for `MmNonPagedPoolStart`, `MmNonPagedPoolEnd`, you ended up at the right place.

`NonPagedPool` in Windows has two variables that defined the start and end of the section in kernel memory. Online blog posts and tutorials show an outdated version of these two variables.

Take a look at [this old post](https://web.archive.org/web/20061110120809/http://www.rootkit.com/newsread.php?newsid=153). `_DBGKD_GET_VERSION64 KdVersionBlock` was a very important structure into the debugger block of Windows. However, if you try to find this structure in Windows 10, you will hit `KdVersionBlock == 0` (Ouch!!!). But this structure provides offset into `MmNonPagedPool{Start,End}`, how can we get those?

Luckily, both `MmNonPagedPoolStart` and `MmNonPagedPoolEnd` in Windows XP, can be found by offseting from `ntoskrnl.exe`. Rekall team are very positive that their tools doesn't rely on profiles file like Volatility but use PDB provided by Windows to find these values.

In [Rekall source code](https://github.com/google/rekall/blob/c5d68e31705f4b5bd2581c1d951b7f6983f7089c/rekall-core/rekall/plugins/windows/pool.py#L87), the values of those variables are:

- Windows XP: `MmNonPagedPool{Start,End}`
- Windows 7 and maybe 8: `MiNonPagedPoolStartAligned`, `MiNonPagedPoolEnd`, and `MiNonPagedPoolBitMap`
- Windows 10 below

In Windows 7, 8, another field was added to controll the allocation of `NonPagedPool`, which is why there is [this paper about pool tag quick scanning](https://www.sciencedirect.com/science/article/pii/S1742287616000062).

However, from Windows 10, the whole game change around when the global offset to those (similar) variables. Instead Windows 10 introduced a new structure `MiState`. `MiState` offset is available and we can get the variables by either:

- Windows 2015: `*((ntoskrnl.exe+MiState)->SystemNodeInformation->NonPagedPool{First,Last}Va)`
- Windows 2016: `*((ntoskrnl.exe+MiState)->Hardware.SystemNodeInformation->NonPagedPool{First,Last}Va)`

The `NonPagedBitMap` was still visible untill the May 2019 Update, here, take a look at these 2 consecutive update [`1809 Redstone 5 (October Update)`](https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/1809%20Redstone%205%20(October%20Update)/\_MI\_SYSTEM\_NODE\_INFORMATION) and [`1903 19H1 (May 2019 Update)`](https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/1903%2019H1%20(May%202019%20Update)/\_MI\_SYSTEM\_NODE\_INFORMATION).

Yeah, now `pool tag quick scanning` is useless (gah). Windows OS changes quite frequently right? Tell you more, I am using the Insider version of Windows in 2020, and guess what, I found out that they put another struct to point to those value. So now we need to go like this:

- Windows 2020 Insider preview: `*((ntoskrnl.exe+MiState)->SystemNodeNonPagedPool->NonPagedPool{First,Last}Va)`

Anyway, I create this project to help me with my thesis, following outdated structs online yields no result. Oh, yeah, a guy seems to be asking on [how to get `MmNonPagedPoolStart`](https://reverseengineering.stackexchange.com/q/6483) on `stackexchange`, too bad [the answer](https://reverseengineering.stackexchange.com/a/6487) is not so much helpful.

Take a look at my ntoskrnl.exe pdb file parsed.

```
PDB for Amd64, guid: 3e7ee354-590f-ac1c-62a8-ccf0b6368989, age: 1,

MiState 0xc4f280 23:324224
KdDebuggerDataBlock 0xc00a30 23:2608

struct _MI_SYSTEM_INFORMATION
  - field _MI_POOL_STATE Pools at offset 0
  - field _MI_SECTION_STATE Sections at offset c0
  - field _MI_SYSTEM_IMAGE_STATE SystemImages at offset 400
  - field _MI_SESSION_STATE Sessions at offset 4a8
  - field _MI_PROCESS_STATE Processes at offset 1550
  - field _MI_HARDWARE_STATE Hardware at offset 15c0
  - field _MI_SYSTEM_VA_STATE SystemVa at offset 1780
  - field _MI_COMBINE_STATE PageCombines at offset 1c40
  - field _MI_PAGELIST_STATE PageLists at offset 1c60
  - field _MI_PARTITION_STATE Partitions at offset 1d00
  - field _MI_SHUTDOWN_STATE Shutdowns at offset 1dc0
  - field _MI_ERROR_STATE Errors at offset 1e38
  - field _MI_ACCESS_LOG_STATE AccessLog at offset 1f40
  - field _MI_DEBUGGER_STATE Debugger at offset 1fc0
  - field _MI_STANDBY_STATE Standby at offset 20e0
  - field _MI_SYSTEM_PTE_STATE SystemPtes at offset 2180
  - field _MI_IO_PAGE_STATE IoPages at offset 2380
  - field _MI_PAGING_IO_STATE PagingIo at offset 2440
  - field _MI_COMMON_PAGE_STATE CommonPages at offset 24f0
  - field _MI_SYSTEM_TRIM_STATE Trims at offset 25c0
  - field _MI_SYSTEM_ZEROING Zeroing at offset 2600
  - field _MI_ENCLAVE_STATE Enclaves at offset 2620
  - field U64 Cookie at offset 2668
  - field Void** BootRegistryRuns at offset 2670
  - field UNNOWN ZeroingDisabled at offset 2678
  - field UChar FullyInitialized at offset 267c
  - field UChar SafeBooted at offset 267d
  - field UNNOWN* TraceLogging at offset 2680
  - field _MI_VISIBLE_STATE Vs at offset 26c0

struct _MI_HARDWARE_STATE
  - field U32 NodeMask at offset 0
  - field U32 NumaHintIndex at offset 4
  - field U32 NumaLastRangeIndexInclusive at offset 8
  - field UChar NodeShift at offset c
  - field UChar ChannelShift at offset d
  - field U32 ChannelHintIndex at offset 10
  - field U32 ChannelLastRangeIndexInclusive at offset 14
  - field _MI_NODE_NUMBER_ZERO_BASED* NodeGraph at offset 18
  - field _MI_SYSTEM_NODE_NONPAGED_POOL* SystemNodeNonPagedPool at offset 20
  - field UNNOWN TemporaryNumaRanges at offset 28
  - field _HAL_NODE_RANGE* NumaMemoryRanges at offset 48
  - field _HAL_CHANNEL_MEMORY_RANGES* ChannelMemoryRanges at offset 50
  - field U32 SecondLevelCacheSize at offset 58
  - field U32 FirstLevelCacheSize at offset 5c
  - field U32 PhysicalAddressBits at offset 60
  - field U32 PfnDatabasePageBits at offset 64
  - field U32 LogicalProcessorsPerCore at offset 68
  - field UChar ProcessorCachesFlushedOnPowerLoss at offset 6c
  - field U64 TotalPagesAllowed at offset 70
  - field U32 SecondaryColorMask at offset 78
  - field U32 SecondaryColors at offset 7c
  - field U32 FlushTbForAttributeChange at offset 80
  - field U32 FlushCacheForAttributeChange at offset 84
  - field U32 FlushCacheForPageAttributeChange at offset 88
  - field U32 CacheFlushPromoteThreshold at offset 8c
  - field _LARGE_INTEGER PerformanceCounterFrequency at offset 90
  - field U64 InvalidPteMask at offset c0
  - field UNNOWN LargePageColors at offset 100
  - field U64 FlushTbThreshold at offset 110
  - field UNNOWN OptimalZeroingAttribute at offset 118
  - field UChar AttributeChangeRequiresReZero at offset 158
  - field UNNOWN ZeroCostCounts at offset 160
  - field U64 HighestPossiblePhysicalPage at offset 180
  - field U64 VsmKernelPageCount at offset 188

struct _MI_SYSTEM_NODE_NONPAGED_POOL
  - field _MI_DYNAMIC_BITMAP DynamicBitMapNonPagedPool at offset 0
  - field U64 CachedNonPagedPoolCount at offset 48
  - field U64 NonPagedPoolSpinLock at offset 50
  - field _MMPFN* CachedNonPagedPool at offset 58
  - field Void NonPagedPoolFirstVa at offset 60
  - field Void NonPagedPoolLastVa at offset 68
  - field _MI_SYSTEM_NODE_INFORMATION* SystemNodeInformation at offset 70

struct _MI_SYSTEM_NODE_INFORMATION
  - field UNNOWN CachedKernelStacks at offset 0
  - field _GROUP_AFFINITY GroupAffinity at offset 40
  - field U16 ProcessorCount at offset 50
  - field Void BootZeroPageTimesPerProcessor at offset 58
  - field U64 CyclesToZeroOneLargePage at offset 60
  - field U64 ScaledCyclesToZeroOneLargePage at offset 68
  - field _MI_WRITE_CALIBRATION WriteCalibration at offset 70
  - field UNNOWN IoPfnLock at offset c0
```
