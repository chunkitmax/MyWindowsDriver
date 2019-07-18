#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif
typedef struct _KSYSTEM_SERVICE_TABLE
{
	PULONG  ServiceTableBase;				
	PULONG  ServiceCounterTableBase;		
	ULONG   NumberOfService;				
	ULONG   ParamTableBase;						

} KSYSTEM_SERVICE_TABLE, *PKSYSTEM_SERVICE_TABLE;


typedef struct _KSERVICE_TABLE_DESCRIPTOR
{
	KSYSTEM_SERVICE_TABLE   ntoskrnl;		
	KSYSTEM_SERVICE_TABLE   win32k;			
	KSYSTEM_SERVICE_TABLE   notUsed1;
	KSYSTEM_SERVICE_TABLE   notUsed2;

} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;

extern PKSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable;
}


#ifdef __cplusplus
extern "C"
{
#endif

struct _SYSTEM_THREADS
{
LARGE_INTEGER KernelTime;
LARGE_INTEGER UserTime;
LARGE_INTEGER CreateTime;
ULONG WaitTime;
PVOID StartAddress;
CLIENT_ID ClientIs;
KPRIORITY Priority;
KPRIORITY BasePriority;
ULONG ContextSwitchCount;
ULONG ThreadState;
KWAIT_REASON WaitReason;
};

typedef struct _SYSTEM_PROCESS_INFORMATION {
  ULONG                   NextEntryOffset;
  ULONG                   NumberOfThreads;
  LARGE_INTEGER           Reserved[3];
  LARGE_INTEGER           CreateTime;
  LARGE_INTEGER           UserTime;
  LARGE_INTEGER           KernelTime;
  UNICODE_STRING          ImageName;
  KPRIORITY               BasePriority;
  HANDLE                  ProcessId;
  HANDLE                  InheritedFromProcessId;
  ULONG                   HandleCount;
  ULONG                   Reserved2[2];
  ULONG                   PrivatePageCount;
  VM_COUNTERS             VirtualMemoryCounters;
  IO_COUNTERS             IoCounters;
  _SYSTEM_THREADS          Threads[1];
} SYSPROCESS, *PSYSPROCESS;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemNextEventIdInformation,
    SystemEventIdsInformation,
    SystemCrashDumpInformation,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemPlugPlayBusInformation,
    SystemDockInformation,
    pSystemPowerInformation,
    SystemProcessorSpeedInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation (
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
	);

typedef NTSTATUS (* NTQUERYSYSTEMINFORMATION)(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
	);

}

#define SYS_INDEX(ServiceFunction) (*(PULONG)((ULONG)ServiceFunction + 1))
#define SYS_FUNCTION(ServiceFunction) KeServiceDescriptorTable->ntoskrnl.ServiceTableBase[SYS_INDEX(ServiceFunction)]


//定義 SSDT(系統服務描述表) 中服務個數的最大數目
//這裡定義為 1024 個，實際上在 XP SP3 是 0x0128 個
#define MAX_SYSTEM_SERVICE_NUMBER 1024

NTSTATUS InstallSSDTHook(ULONG OldService, ULONG NewService);
NTSTATUS UnInstallSSDTHook(ULONG OldService);
VOID EnableWriteProtect(ULONG OldProtect);
VOID DisableWriteProtect(PULONG OldProtect);
VOID BackUpSSDT();

ULONG OldSSDTAddress[MAX_SYSTEM_SERVICE_NUMBER];
ULONG OldNtQuerySystemInformation = 0;

VOID EnableWriteProtect(ULONG OldProtect)
{
	_asm
	{
		mov eax, OldProtect
		mov cr0, eax
		sti;
	}
}

VOID DisableWriteProtect(PULONG OldProtect)
{
	ULONG Attr;
	_asm
	{
		cli;
		mov eax, cr0;
		mov Attr, eax;
		and eax, 0FFFEFFFFh;
		mov cr0, eax;
	};

	*OldProtect = Attr;
}

VOID BackUpSSDT()
{
	ULONG Counter = 0;

	KdPrint(("[MyDriver] Making backup!"));
	for(Counter; (Counter < KeServiceDescriptorTable->ntoskrnl.NumberOfService) && (Counter < MAX_SYSTEM_SERVICE_NUMBER) ; Counter++)
	{
		OldSSDTAddress[Counter] = KeServiceDescriptorTable->ntoskrnl.ServiceTableBase[Counter];
		KdPrint(("[MyDriver] SSDT Information { Number : 0x%04X , Address : 0x%08X", Counter, OldSSDTAddress[Counter]));
	}
}

NTSTATUS InstallSSDTHook(ULONG OldService, ULONG NewService)
{
	ULONG OldWP;
	DisableWriteProtect(&OldWP);
	SYS_FUNCTION(OldService) = NewService;
	//KeServiceDescriptorTable->ntoskrnl.ServiceTableBase[SYSCALL_INDEX(oldService)] = newService;
	EnableWriteProtect(OldWP);
	OldNtQuerySystemInformation = OldSSDTAddress[SYS_INDEX(ZwQuerySystemInformation)];
	KdPrint(("OldNtQuerySystemInformation Address : 0x%08X", OldNtQuerySystemInformation));
	KdPrint(("[MyDriver] InstallSSDTHook Success!"));
	return STATUS_SUCCESS;
}

NTSTATUS UnInstallSSDTHook(ULONG OldService)
{
	ULONG OldWP;
	DisableWriteProtect(&OldWP);
	SYS_FUNCTION(OldService) = OldSSDTAddress[SYS_INDEX(OldService)];
	EnableWriteProtect(OldWP);
	return STATUS_SUCCESS;
}