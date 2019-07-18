#include <ntddk.h>

#define MYDEVICE_DEVICE_NAME     L"\\Device\\MyDriver"
#define MYDEVICE_DOS_DEVICE_NAME L"\\DosDevices\\MyDriver"

typedef struct _SERVICE_DESCRIPTOR_TABLE
{
PULONG ServiceTable;
PULONG ServiceCounterTable;
ULONG NumberOfService;
ULONG ParamTableBase;
}SERVICE_DESCRIPTOR_TABLE,*PSERVICE_DESCRIPTOR_TABLE;

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

typedef struct _DEVICE_EXTENSION
{
    ULONG StateVariable;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

extern "C"
NTKERNELAPI
NTSTATUS ZwQuerySystemInformation(
        IN  ULONG SystemInformationClass,
        IN  OUT PVOID SystemInformation,
        IN  ULONG SystemInformationLength,
        OUT PULONG ReturnLength OPTIONAL
);

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject);

PWCH TargetProcessName = L"Student.exe";

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	
//  Main;
	HANDLE hp = 0;
	OBJECT_ATTRIBUTES OA;
	CLIENT_ID cid;
	NTSTATUS ntstatus = STATUS_SUCCESS;
	ULONG ReturnSize;
	PVOID ProcessInfo;
	PSYSPROCESS ProcessList;
	PWCH ProcessName;

		ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &ReturnSize);
		if(!ReturnSize)
			return STATUS_UNSUCCESSFUL;
		ProcessInfo = ExAllocatePool(PagedPool, ReturnSize);
		if((ULONG)ProcessInfo != 0)
		{
			ntstatus = ZwQuerySystemInformation(SystemProcessInformation, ProcessInfo, ReturnSize, 0);
			if(NT_SUCCESS(ntstatus))
			{
				ProcessList = (PSYSPROCESS)ProcessInfo;
				while(ProcessList)
				{
					ProcessName = ProcessList->ImageName.Buffer;
					if(ProcessName)
					{
						if(wcscmp(ProcessName, TargetProcessName) == 0)
						{
							KdPrint(("[MyDriver] %S is found!", TargetProcessName));
							KdPrint(("[MyDriver] TargetProcessId : %d", ProcessList->ProcessId));
							KdPrint(("[MyDriver] ProcessName : %S", ProcessName));
							KdPrint(("[MyDriver] ProcessNameLength : %d", ProcessList->ImageName.Length));
							cid.UniqueProcess = (HANDLE)ProcessList->ProcessId;
							cid.UniqueThread = 0;
							InitializeObjectAttributes(&OA, 0, 0, 0, 0);
							ntstatus = ZwOpenProcess(&hp, PROCESS_ALL_ACCESS, &OA, &cid);
							if(NT_SUCCESS(ntstatus))
							{
								KdPrint(("[MyDriver] NtOpneProcess Success! Handle: %d", hp));
								ntstatus = ZwTerminateProcess(hp, 0);
								if(NT_SUCCESS(ntstatus))
									KdPrint(("[MyDriver] NtTerminateProcess Success!"));
								else
									KdPrint(("[MyDriver] NtTerminateProcess Failed! ReturnValue : %X", ntstatus));
							}else
							{
								KdPrint(("[MyDriver] NtOpenProcess Failed! ErrorCode: %d", ntstatus));
							}
						}
					}
					if(ProcessList->NextEntryOffset)
					{
						ProcessName = L"";
						ProcessList = (PSYSPROCESS)((ULONG)ProcessList + ProcessList->NextEntryOffset);
					}
					else
					{
						ProcessList = NULL;
					}
				}
			}
		}
		ExFreePool(ProcessInfo);

// End;
	/*
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING DeviceName,DosDeviceName;
	PDEVICE_OBJECT DeviceObject = NULL;

	KdPrint(("[MyDriver] DriverEntry: %wZ\n", RegistryPath));
	RtlInitUnicodeString(&DeviceName, MYDEVICE_DEVICE_NAME);
	status = IoCreateDevice(DriverObject, sizeof(DEVICE_EXTENSION), &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	if(!NT_SUCCESS(status))
	{
		KdPrint(("[MyDriver] IoCreateDevice Failed!"));
		return status;
	}
	RtlInitUnicodeString(&DosDeviceName, MYDEVICE_DOS_DEVICE_NAME);
	status = IoCreateSymbolicLink(&DosDeviceName, &DeviceName);
	if(!NT_SUCCESS(status))
	{
		KdPrint(("[MyDriver] IoSymbolicLink Failed!"));
		IoDeleteDevice(DeviceObject);
		return status;
	}
	*/
	DriverObject->DriverUnload = DriverUnload;

	KdPrint(("[MyDriver] Leave DriverEntry"));
	return STATUS_SUCCESS;
}

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
/*	UNICODE_STRING dosDeviceName;

	RtlInitUnicodeString(&dosDeviceName, MYDEVICE_DOS_DEVICE_NAME);
	IoDeleteSymbolicLink(&dosDeviceName);
	IoDeleteDevice(DriverObject->DeviceObject);
	*/
	KdPrint(("[MyDriver] Unloaded!"));
}