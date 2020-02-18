> If you came here for `MmNonPagedPoolStart`, `MmNonPagedPoolEnd`, you ended up at the right place.

`NonPagedPool` in Windows has two variables that defined the start and end of the section in kernel memory. Online blog posts and tutorials show an outdated version of these two variables.

Take a look at [this old post](https://web.archive.org/web/20061110120809/http://www.rootkit.com/newsread.php?newsid=153). `_DBGKD_GET_VERSION64 KdVersionBlock` was a very important structure into the debugger block of Windows. However, if you try to find this structure in Windows 10, you will hit `KdVersionBlock == 0` (Ouch!!!). But this structure provides offset into `MmNonPagedPool{Start,End}`, how can we get those?

Luckily, both `MmNonPagedPoolStart` and `MmNonPagedPoolEnd` in Windows XP, can be found by offseting from `ntoskrnl.exe`. Rekall team are very positive that their tools doesn't rely on profiles file like Volatility but use PDB provided by Windows to find these values.

In [Rekall source code](https://github.com/google/rekall/blob/c5d68e31705f4b5bd2581c1d951b7f6983f7089c/rekall-core/rekall/plugins/windows/pool.py#L87), the values of those variables are:

- Windows XP: `MmNonPagedPool{Start,End}`
- Windows 7 and maybe 8: `MiNonPagedPoolStartAligned`, `MiNonPagedPoolEnd`, and `MiNonPagedPoolBitMap`
- Windows 10 below

In Windows 7, 8, another field was added to controll the allocation of `NonPagedPool`, which is why there is [this paper about pool tag quick scanning](https://www.sciencedirect.com/science/article/pii/S1742287616000062).

However, from Windows 10, the whole game changed around when the global offset to those (similar) variables are gone. Instead Windows 10 introduced a new variable `MiState`. `MiState` offset is available and we can get those start/end variables by either:

- Windows 2015: `*((ntoskrnl.exe+MiState)->SystemNodeInformation->NonPagedPool{First,Last}Va)`
- Windows 2016: `*((ntoskrnl.exe+MiState)->Hardware.SystemNodeInformation->NonPagedPool{First,Last}Va)`

The `NonPagedBitMap` was still visible untill the May 2019 Update, here, take a look at these 2 consecutive update [`1809 Redstone 5 (October Update)`](https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/1809%20Redstone%205%20(October%20Update)/\_MI\_SYSTEM\_NODE\_INFORMATION) and [`1903 19H1 (May 2019 Update)`](https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/1903%2019H1%20(May%202019%20Update)/\_MI\_SYSTEM\_NODE\_INFORMATION).

Yeah, now `pool tag quick scanning` is useless (gah). Windows OS changes quite frequently right? Tell you more, I am using the Insider version of Windows in 2020, and guess what, I found out that they put another struct to point to those value. So now we need to go like this:

- Windows 2020 Insider preview: `*((ntoskrnl.exe+MiState)->SystemNodeNonPagedPool->NonPagedPool{First,Last}Va)`

> If you go with low-level, then you only care about the offset and formula to get those variables but knowing the structure is well benefit.

Anyway, I create this project to help me with my thesis, following outdated structs online yields no result. Oh, yeah, a guy seems to be asking on [how to get `MmNonPagedPoolStart`](https://reverseengineering.stackexchange.com/q/6483) on `stackexchange`, too bad [the answer](https://reverseengineering.stackexchange.com/a/6487) is not so much helpful.

Take a look at my ntoskrnl.exe pdb file parsed.

```
PDB for Amd64, guid: 3c6978d6-66d9-c05a-53b6-a1e1561282c8, age: 1,

Void(UNNOWN) PsActiveProcessHead 0xc1f970 23:129392
Void(UNNOWN) MiState 0xc4f200 23:324096
Void(UNNOWN) KeNumberNodes 0xcfc000 24:0
Void(UNNOWN) PsLoadedModuleList 0xc2ba30 23:178736
Void(UNNOWN) KdDebuggerDataBlock 0xc00a30 23:2608

beginstruct _LIST_ENTRY
	0x0 _LIST_ENTRY* Flink
	0x8 _LIST_ENTRY* Blink
endstruct

beginstruct _RTL_BITMAP
	0x0 U32 SizeOfBitMap
	0x8 U32 Buffer
endstruct

beginstruct _EPROCESS
	0x0 _KPROCESS Pcb
	0x438 _EX_PUSH_LOCK ProcessLock
	0x440 Void UniqueProcessId
	0x448 _LIST_ENTRY ActiveProcessLinks
	0x458 _EX_RUNDOWN_REF RundownProtect
	0x460 U32 Flags2
	0x460 UNNOWN JobNotReallyActive
	0x460 UNNOWN AccountingFolded
	0x460 UNNOWN NewProcessReported
	0x460 UNNOWN ExitProcessReported
	0x460 UNNOWN ReportCommitChanges
	0x460 UNNOWN LastReportMemory
	0x460 UNNOWN ForceWakeCharge
	0x460 UNNOWN CrossSessionCreate
	0x460 UNNOWN NeedsHandleRundown
	0x460 UNNOWN RefTraceEnabled
	0x460 UNNOWN PicoCreated
	0x460 UNNOWN EmptyJobEvaluated
	0x460 UNNOWN DefaultPagePriority
	0x460 UNNOWN PrimaryTokenFrozen
	0x460 UNNOWN ProcessVerifierTarget
	0x460 UNNOWN RestrictSetThreadContext
	0x460 UNNOWN AffinityPermanent
	0x460 UNNOWN AffinityUpdateEnable
	0x460 UNNOWN PropagateNode
	0x460 UNNOWN ExplicitAffinity
	0x460 UNNOWN ProcessExecutionState
	0x460 UNNOWN EnableReadVmLogging
	0x460 UNNOWN EnableWriteVmLogging
	0x460 UNNOWN FatalAccessTerminationRequested
	0x460 UNNOWN DisableSystemAllowedCpuSet
	0x460 UNNOWN ProcessStateChangeRequest
	0x460 UNNOWN ProcessStateChangeInProgress
	0x460 UNNOWN InPrivate
	0x464 U32 Flags
	0x464 UNNOWN CreateReported
	0x464 UNNOWN NoDebugInherit
	0x464 UNNOWN ProcessExiting
	0x464 UNNOWN ProcessDelete
	0x464 UNNOWN ManageExecutableMemoryWrites
	0x464 UNNOWN VmDeleted
	0x464 UNNOWN OutswapEnabled
	0x464 UNNOWN Outswapped
	0x464 UNNOWN FailFastOnCommitFail
	0x464 UNNOWN Wow64VaSpace4Gb
	0x464 UNNOWN AddressSpaceInitialized
	0x464 UNNOWN SetTimerResolution
	0x464 UNNOWN BreakOnTermination
	0x464 UNNOWN DeprioritizeViews
	0x464 UNNOWN WriteWatch
	0x464 UNNOWN ProcessInSession
	0x464 UNNOWN OverrideAddressSpace
	0x464 UNNOWN HasAddressSpace
	0x464 UNNOWN LaunchPrefetched
	0x464 UNNOWN Background
	0x464 UNNOWN VmTopDown
	0x464 UNNOWN ImageNotifyDone
	0x464 UNNOWN PdeUpdateNeeded
	0x464 UNNOWN VdmAllowed
	0x464 UNNOWN ProcessRundown
	0x464 UNNOWN ProcessInserted
	0x464 UNNOWN DefaultIoPriority
	0x464 UNNOWN ProcessSelfDelete
	0x464 UNNOWN SetTimerResolutionLink
	0x468 _LARGE_INTEGER CreateTime
	0x470 U64[16] ProcessQuotaUsage
	0x480 U64[16] ProcessQuotaPeak
	0x490 U64 PeakVirtualSize
	0x498 U64 VirtualSize
	0x4a0 _LIST_ENTRY SessionProcessLinks
	0x4b0 Void ExceptionPortData
	0x4b0 U64 ExceptionPortValue
	0x4b0 UNNOWN ExceptionPortState
	0x4b8 _EX_FAST_REF Token
	0x4c0 U64 MmReserved
	0x4c8 _EX_PUSH_LOCK AddressCreationLock
	0x4d0 _EX_PUSH_LOCK PageTableCommitmentLock
	0x4d8 _ETHREAD* RotateInProgress
	0x4e0 _ETHREAD* ForkInProgress
	0x4e8 _EJOB* CommitChargeJob
	0x4f0 _RTL_AVL_TREE CloneRoot
	0x4f8 volatile U64 NumberOfPrivatePages
	0x500 volatile U64 NumberOfLockedPages
	0x508 Void Win32Process
	0x510 _EJOB* Job
	0x518 Void SectionObject
	0x520 Void SectionBaseAddress
	0x528 U32 Cookie
	0x530 _PAGEFAULT_HISTORY* WorkingSetWatch
	0x538 Void Win32WindowStation
	0x540 Void InheritedFromUniqueProcessId
	0x548 volatile U64 OwnerProcessId
	0x550 _PEB* Peb
	0x558 _MM_SESSION_SPACE* Session
	0x560 Void Spare1
	0x568 _EPROCESS_QUOTA_BLOCK* QuotaBlock
	0x570 _HANDLE_TABLE* ObjectTable
	0x578 Void DebugPort
	0x580 _EWOW64PROCESS* WoW64Process
	0x588 Void DeviceMap
	0x590 Void EtwDataSource
	0x598 U64 PageDirectoryPte
	0x5a0 _FILE_OBJECT* ImageFilePointer
	0x5a8 UChar[15] ImageFileName
	0x5b7 UChar PriorityClass
	0x5b8 Void SecurityPort
	0x5c0 _SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo
	0x5c8 _LIST_ENTRY JobLinks
	0x5d8 Void HighestUserAddress
	0x5e0 _LIST_ENTRY ThreadListHead
	0x5f0 volatile U32 ActiveThreads
	0x5f4 U32 ImagePathHash
	0x5f8 U32 DefaultHardErrorProcessing
	0x5fc I32 LastThreadExitStatus
	0x600 _EX_FAST_REF PrefetchTrace
	0x608 Void LockedPagesList
	0x610 _LARGE_INTEGER ReadOperationCount
	0x618 _LARGE_INTEGER WriteOperationCount
	0x620 _LARGE_INTEGER OtherOperationCount
	0x628 _LARGE_INTEGER ReadTransferCount
	0x630 _LARGE_INTEGER WriteTransferCount
	0x638 _LARGE_INTEGER OtherTransferCount
	0x640 U64 CommitChargeLimit
	0x648 volatile U64 CommitCharge
	0x650 volatile U64 CommitChargePeak
	0x680 _MMSUPPORT_FULL Vm
	0x7c0 _LIST_ENTRY MmProcessLinks
	0x7d0 U32 ModifiedPageCount
	0x7d4 I32 ExitStatus
	0x7d8 _RTL_AVL_TREE VadRoot
	0x7e0 Void VadHint
	0x7e8 U64 VadCount
	0x7f0 volatile U64 VadPhysicalPages
	0x7f8 U64 VadPhysicalPagesLimit
	0x800 _ALPC_PROCESS_CONTEXT AlpcContext
	0x820 _LIST_ENTRY TimerResolutionLink
	0x830 _PO_DIAG_STACK_RECORD* TimerResolutionStackRecord
	0x838 U32 RequestedTimerResolution
	0x83c U32 SmallestTimerResolution
	0x840 _LARGE_INTEGER ExitTime
	0x848 _INVERTED_FUNCTION_TABLE* InvertedFunctionTable
	0x850 _EX_PUSH_LOCK InvertedFunctionTableLock
	0x858 U32 ActiveThreadsHighWatermark
	0x85c U32 LargePrivateVadCount
	0x860 _EX_PUSH_LOCK ThreadListLock
	0x868 Void WnfContext
	0x870 _EJOB* ServerSilo
	0x878 UChar SignatureLevel
	0x879 UChar SectionSignatureLevel
	0x87a _PS_PROTECTION Protection
	0x87b UNNOWN HangCount
	0x87b UNNOWN GhostCount
	0x87b UNNOWN PrefilterException
	0x87c U32 Flags3
	0x87c UNNOWN Minimal
	0x87c UNNOWN ReplacingPageRoot
	0x87c UNNOWN Crashed
	0x87c UNNOWN JobVadsAreTracked
	0x87c UNNOWN VadTrackingDisabled
	0x87c UNNOWN AuxiliaryProcess
	0x87c UNNOWN SubsystemProcess
	0x87c UNNOWN IndirectCpuSets
	0x87c UNNOWN RelinquishedCommit
	0x87c UNNOWN HighGraphicsPriority
	0x87c UNNOWN CommitFailLogged
	0x87c UNNOWN ReserveFailLogged
	0x87c UNNOWN SystemProcess
	0x87c UNNOWN HideImageBaseAddresses
	0x87c UNNOWN AddressPolicyFrozen
	0x87c UNNOWN ProcessFirstResume
	0x87c UNNOWN ForegroundExternal
	0x87c UNNOWN ForegroundSystem
	0x87c UNNOWN HighMemoryPriority
	0x87c UNNOWN EnableProcessSuspendResumeLogging
	0x87c UNNOWN EnableThreadSuspendResumeLogging
	0x87c UNNOWN SecurityDomainChanged
	0x87c UNNOWN SecurityFreezeComplete
	0x87c UNNOWN VmProcessorHost
	0x87c UNNOWN VmProcessorHostTransition
	0x87c UNNOWN AltSyscall
	0x87c UNNOWN TimerResolutionIgnore
	0x880 I32 DeviceAsid
	0x888 Void SvmData
	0x890 _EX_PUSH_LOCK SvmProcessLock
	0x898 U64 SvmLock
	0x8a0 _LIST_ENTRY SvmProcessDeviceListHead
	0x8b0 U64 LastFreezeInterruptTime
	0x8b8 _PROCESS_DISK_COUNTERS* DiskCounters
	0x8c0 Void PicoContext
	0x8c8 Void EnclaveTable
	0x8d0 U64 EnclaveNumber
	0x8d8 _EX_PUSH_LOCK EnclaveLock
	0x8e0 U32 HighPriorityFaultsAllowed
	0x8e8 _PO_PROCESS_ENERGY_CONTEXT* EnergyContext
	0x8f0 Void VmContext
	0x8f8 U64 SequenceNumber
	0x900 U64 CreateInterruptTime
	0x908 U64 CreateUnbiasedInterruptTime
	0x910 U64 TotalUnbiasedFrozenTime
	0x918 U64 LastAppStateUpdateTime
	0x920 UNNOWN LastAppStateUptime
	0x920 UNNOWN LastAppState
	0x928 volatile U64 SharedCommitCharge
	0x930 _EX_PUSH_LOCK SharedCommitLock
	0x938 _LIST_ENTRY SharedCommitLinks
	0x948 U64 AllowedCpuSets
	0x950 U64 DefaultCpuSets
	0x948 U64 AllowedCpuSetsIndirect
	0x950 U64 DefaultCpuSetsIndirect
	0x958 Void DiskIoAttribution
	0x960 Void DxgProcess
	0x968 U32 Win32KFilterSet
	0x970 volatile _PS_INTERLOCKED_TIMER_DELAY_VALUES ProcessTimerDelay
	0x978 volatile U32 KTimerSets
	0x97c volatile U32 KTimer2Sets
	0x980 volatile U32 ThreadTimerSets
	0x988 U64 VirtualTimerListLock
	0x990 _LIST_ENTRY VirtualTimerListHead
	0x9a0 _WNF_STATE_NAME WakeChannel
	0x9a0 _PS_PROCESS_WAKE_INFORMATION WakeInfo
	0x9d0 U32 MitigationFlags
	0x9d0 <anonymous-tag> MitigationFlagsValues
	0x9d4 U32 MitigationFlags2
	0x9d4 <anonymous-tag> MitigationFlags2Values
	0x9d8 Void PartitionObject
	0x9e0 U64 SecurityDomain
	0x9e8 U64 ParentSecurityDomain
	0x9f0 Void CoverageSamplerContext
	0x9f8 Void MmHotPatchContext
	0xa00 _KE_IDEAL_PROCESSOR_ASSIGNMENT_BLOCK IdealProcessorAssignmentBlock
	0xab8 _RTL_AVL_TREE DynamicEHContinuationTargetsTree
	0xac0 _EX_PUSH_LOCK DynamicEHContinuationTargetsLock
endstruct

beginstruct _RTL_BITMAP_EX
	0x0 U64 SizeOfBitMap
	0x8 U64 Buffer
endstruct

beginstruct _MI_SYSTEM_INFORMATION
	0x0 _MI_POOL_STATE Pools
	0xc0 _MI_SECTION_STATE Sections
	0x400 _MI_SYSTEM_IMAGE_STATE SystemImages
	0x4a8 _MI_SESSION_STATE Sessions
	0x1530 _MI_PROCESS_STATE Processes
	0x1580 _MI_HARDWARE_STATE Hardware
	0x1740 _MI_SYSTEM_VA_STATE SystemVa
	0x1c00 _MI_COMBINE_STATE PageCombines
	0x1c20 _MI_PAGELIST_STATE PageLists
	0x1cc0 _MI_PARTITION_STATE Partitions
	0x1d80 _MI_SHUTDOWN_STATE Shutdowns
	0x1df8 _MI_ERROR_STATE Errors
	0x1f00 _MI_ACCESS_LOG_STATE AccessLog
	0x1f80 _MI_DEBUGGER_STATE Debugger
	0x20a0 _MI_STANDBY_STATE Standby
	0x2140 _MI_SYSTEM_PTE_STATE SystemPtes
	0x2340 _MI_IO_PAGE_STATE IoPages
	0x2400 _MI_PAGING_IO_STATE PagingIo
	0x24b0 _MI_COMMON_PAGE_STATE CommonPages
	0x2580 _MI_SYSTEM_TRIM_STATE Trims
	0x25c0 _MI_SYSTEM_ZEROING Zeroing
	0x25e0 _MI_ENCLAVE_STATE Enclaves
	0x2628 U64 Cookie
	0x2630 Void** BootRegistryRuns
	0x2638 volatile I32 ZeroingDisabled
	0x263c UChar FullyInitialized
	0x263d UChar SafeBooted
	0x2640 const _tlgProvider_t* TraceLogging
	0x2680 _MI_VISIBLE_STATE Vs
endstruct

beginstruct _PEB
	0x0 UChar InheritedAddressSpace
	0x1 UChar ReadImageFileExecOptions
	0x2 UChar BeingDebugged
	0x3 UChar BitField
	0x3 UNNOWN ImageUsesLargePages
	0x3 UNNOWN IsProtectedProcess
	0x3 UNNOWN IsImageDynamicallyRelocated
	0x3 UNNOWN SkipPatchingUser32Forwarders
	0x3 UNNOWN IsPackagedProcess
	0x3 UNNOWN IsAppContainer
	0x3 UNNOWN IsProtectedProcessLight
	0x3 UNNOWN IsLongPathAwareProcess
	0x4 UChar[4] Padding0
	0x8 Void Mutant
	0x10 Void ImageBaseAddress
	0x18 _PEB_LDR_DATA* Ldr
	0x20 _RTL_USER_PROCESS_PARAMETERS* ProcessParameters
	0x28 Void SubSystemData
	0x30 Void ProcessHeap
	0x38 _RTL_CRITICAL_SECTION* FastPebLock
	0x40 _SLIST_HEADER* AtlThunkSListPtr
	0x48 Void IFEOKey
	0x50 U32 CrossProcessFlags
	0x50 UNNOWN ProcessInJob
	0x50 UNNOWN ProcessInitializing
	0x50 UNNOWN ProcessUsingVEH
	0x50 UNNOWN ProcessUsingVCH
	0x50 UNNOWN ProcessUsingFTH
	0x50 UNNOWN ProcessPreviouslyThrottled
	0x50 UNNOWN ProcessCurrentlyThrottled
	0x50 UNNOWN ProcessImagesHotPatched
	0x50 UNNOWN ReservedBits0
	0x54 UChar[4] Padding1
	0x58 Void KernelCallbackTable
	0x58 Void UserSharedInfoPtr
	0x60 U32 SystemReserved
	0x64 U32 AtlThunkSListPtr32
	0x68 Void ApiSetMap
	0x70 U32 TlsExpansionCounter
	0x74 UChar[4] Padding2
	0x78 Void TlsBitmap
	0x80 U32[8] TlsBitmapBits
	0x88 Void ReadOnlySharedMemoryBase
	0x90 Void SharedData
	0x98 Void* ReadOnlyStaticServerData
	0xa0 Void AnsiCodePageData
	0xa8 Void OemCodePageData
	0xb0 Void UnicodeCaseTableData
	0xb8 U32 NumberOfProcessors
	0xbc U32 NtGlobalFlag
	0xc0 _LARGE_INTEGER CriticalSectionTimeout
	0xc8 U64 HeapSegmentReserve
	0xd0 U64 HeapSegmentCommit
	0xd8 U64 HeapDeCommitTotalFreeThreshold
	0xe0 U64 HeapDeCommitFreeBlockThreshold
	0xe8 U32 NumberOfHeaps
	0xec U32 MaximumNumberOfHeaps
	0xf0 Void* ProcessHeaps
	0xf8 Void GdiSharedHandleTable
	0x100 Void ProcessStarterHelper
	0x108 U32 GdiDCAttributeList
	0x10c UChar[4] Padding3
	0x110 _RTL_CRITICAL_SECTION* LoaderLock
	0x118 U32 OSMajorVersion
	0x11c U32 OSMinorVersion
	0x120 U16 OSBuildNumber
	0x122 U16 OSCSDVersion
	0x124 U32 OSPlatformId
	0x128 U32 ImageSubsystem
	0x12c U32 ImageSubsystemMajorVersion
	0x130 U32 ImageSubsystemMinorVersion
	0x134 UChar[4] Padding4
	0x138 U64 ActiveProcessAffinityMask
	0x140 U32[240] GdiHandleBuffer
	0x230 Void(UNNOWN)* PostProcessInitRoutine
	0x238 Void TlsExpansionBitmap
	0x240 U32[128] TlsExpansionBitmapBits
	0x2c0 U32 SessionId
	0x2c4 UChar[4] Padding5
	0x2c8 _ULARGE_INTEGER AppCompatFlags
	0x2d0 _ULARGE_INTEGER AppCompatFlagsUser
	0x2d8 Void pShimData
	0x2e0 Void AppCompatInfo
	0x2e8 _UNICODE_STRING CSDVersion
	0x2f8 const _ACTIVATION_CONTEXT_DATA* ActivationContextData
	0x300 _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap
	0x308 const _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData
	0x310 _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap
	0x318 U64 MinimumStackCommit
	0x320 Void[32] SparePointers
	0x340 U32[20] SpareUlongs
	0x358 Void WerRegistrationData
	0x360 Void WerShipAssertPtr
	0x368 Void pUnused
	0x370 Void pImageHeaderHash
	0x378 U32 TracingFlags
	0x378 UNNOWN HeapTracingEnabled
	0x378 UNNOWN CritSecTracingEnabled
	0x378 UNNOWN LibLoaderTracingEnabled
	0x378 UNNOWN SpareTracingBits
	0x37c UChar[4] Padding6
	0x380 U64 CsrServerReadOnlySharedMemoryBase
	0x388 U64 TppWorkerpListLock
	0x390 _LIST_ENTRY TppWorkerpList
	0x3a0 Void[1024] WaitOnAddressHashTable
	0x7a0 Void TelemetryCoverageHeader
	0x7a8 U32 CloudFileFlags
	0x7ac U32 CloudFileDiagFlags
	0x7b0 RChar PlaceholderCompatibilityMode
	0x7b1 RChar[7] PlaceholderCompatibilityModeReserved
	0x7b8 _LEAP_SECOND_DATA* LeapSecondData
	0x7c0 U32 LeapSecondFlags
	0x7c0 UNNOWN SixtySecondEnabled
	0x7c0 UNNOWN Reserved
	0x7c4 U32 NtGlobalFlag2
endstruct

beginstruct _MI_DYNAMIC_BITMAP
	0x0 _RTL_BITMAP_EX Bitmap
	0x10 U64 MaximumSize
	0x18 U64 Hint
	0x20 Void BaseVa
	0x28 U64 SizeTopDown
	0x30 U64 HintTopDown
	0x38 Void BaseVaTopDown
	0x40 U64 SpinLock
endstruct

beginstruct _MI_HARDWARE_STATE
	0x0 U32 NodeMask
	0x4 U32 NumaHintIndex
	0x8 U32 NumaLastRangeIndexInclusive
	0xc UChar NodeShift
	0xd UChar ChannelShift
	0x10 U32 ChannelHintIndex
	0x14 U32 ChannelLastRangeIndexInclusive
	0x18 _MI_NODE_NUMBER_ZERO_BASED* NodeGraph
	0x20 _MI_SYSTEM_NODE_NONPAGED_POOL* SystemNodeNonPagedPool
	0x28 _HAL_NODE_RANGE[32] TemporaryNumaRanges
	0x48 _HAL_NODE_RANGE* NumaMemoryRanges
	0x50 _HAL_CHANNEL_MEMORY_RANGES* ChannelMemoryRanges
	0x58 U32 SecondLevelCacheSize
	0x5c U32 FirstLevelCacheSize
	0x60 U32 PhysicalAddressBits
	0x64 U32 PfnDatabasePageBits
	0x68 U32 LogicalProcessorsPerCore
	0x6c UChar ProcessorCachesFlushedOnPowerLoss
	0x70 U64 TotalPagesAllowed
	0x78 U32 SecondaryColorMask
	0x7c U32 SecondaryColors
	0x80 U32 FlushTbForAttributeChange
	0x84 U32 FlushCacheForAttributeChange
	0x88 U32 FlushCacheForPageAttributeChange
	0x8c U32 CacheFlushPromoteThreshold
	0x90 _LARGE_INTEGER PerformanceCounterFrequency
	0xc0 U64 InvalidPteMask
	0x100 U32[12] LargePageColors
	0x110 U64 FlushTbThreshold
	0x118 _MI_PFN_CACHE_ATTRIBUTE[16][64] OptimalZeroingAttribute
	0x158 UChar AttributeChangeRequiresReZero
	0x160 _MI_ZERO_COST_COUNTS[32] ZeroCostCounts
	0x180 U64 HighestPossiblePhysicalPage
	0x188 U64 VsmKernelPageCount
endstruct

beginstruct _MI_SYSTEM_NODE_NONPAGED_POOL
	0x0 _MI_DYNAMIC_BITMAP DynamicBitMapNonPagedPool
	0x48 U64 CachedNonPagedPoolCount
	0x50 U64 NonPagedPoolSpinLock
	0x58 _MMPFN* CachedNonPagedPool
	0x60 Void NonPagedPoolFirstVa
	0x68 Void NonPagedPoolLastVa
	0x70 _MI_SYSTEM_NODE_INFORMATION* SystemNodeInformation
endstruct

beginstruct _MI_SYSTEM_NODE_INFORMATION
	0x0 _CACHED_KSTACK_LIST[64] CachedKernelStacks
	0x40 _GROUP_AFFINITY GroupAffinity
	0x50 U16 ProcessorCount
	0x58 Void BootZeroPageTimesPerProcessor
	0x60 U64 CyclesToZeroOneLargePage
	0x68 U64 ScaledCyclesToZeroOneLargePage
	0x70 _MI_WRITE_CALIBRATION WriteCalibration
	0xc0 volatile I32 IoPfnLock
endstruct

```

----

Global variables offset are parsed and can be queried by `nt!` in Windbg. In a kernel driver, we need to get the kernel base address (which is `nt!`). Kernel base address is the loaded address of `ntoskrnl.exe`. There is a shellcode to get the address [here](https://gist.github.com/Barakat/34e9924217ed81fd78c9c92d746ec9c6), using IDT table. But when I use the shellcode with the Windows Insider preview 2020, the address is wrong (it still a loaded PE though). Other ways to get the address are listed [here](https://m0uk4.gitbook.io/notebooks/mouka/windowsinternal/find-kernel-module-address-todo). And hereby I present another way to get the kernel base address.

A device driver can get a pointer to a `EPROCESS` through the use of `PEPROCESS IoGetCurrentProcess`. And as we know, `EPROCESS` has pointer to other `EPROCESS` as a doubly linked list. If we dump them all out, we can notice a few things:

- The image name returned by calling `IoGetCurrentProcess` is `System`
- The `EPROCESS` before `System` is somehow empty

```cpp
PVOID eprocess = (PVOID)IoGetCurrentProcess();
DbgPrint("eprocess : 0x%p, [%15s]\n", eprocess, (char*)((ULONG64)eprocess + ImageBaseNameOffset));
for (int i = 0; i < 100; i++) {
  eprocess = (PVOID)(*(ULONG64*)((ULONG64)eprocess + ActiveProcessLinksOffset) - ActiveProcessLinksOffset);
  DbgPrint("eprocess : 0x%p, [%15s]\n", eprocess, (char*)((ULONG64)eprocess + ImageBaseOffset));
}

// TODO: update output

```

And if we debug and compare the address of that `Empty EPROCESS+ActiveProcessLinksOffset` with `nt!PsActiveProcessHead`, it is just the same. And with the given offset parsed from the PDB file, we can get kernel base address.

```cpp
PVOID eprocess = (PVOID)IoGetCurrentProcess();
DbgPrint("eprocess               : 0x%p, [%15s]\n", eprocess, (char*)((ULONG64)eprocess + ImageBaseNameOffset));
PVOID processHead = (PVOID)(*(ULONG64*)((ULONG64)eprocess + ActiveProcessLinksOffset + BLinkOffset));
DbgPrint("PsActiveProcessHead    : 0x%p\n", processHead);
PVOID ntosbase = (PVOID)((ULONG64)processHead - ActiveHeadOffset);
DbgPrint("ntoskrnl.exe           : 0x%p\n", ntosbase);
```

From now we have successfully get the kernel base address to index into other global variables.

(In this way we use `PsActiveProcessHead`, but a better way maybe traversing `PsLoadedModuleList` which could get the correct address of `ntoskrnl.exe` but I do not know)
