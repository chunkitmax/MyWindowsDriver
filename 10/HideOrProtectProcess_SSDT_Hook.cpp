#include <ntddk.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define MYDEVICE_DEVICE_NAME     L"\\Device\\MyDriver"
#define MYDEVICE_DOS_DEVICE_NAME L"\\??\\MyDriver"
#define IPR_MJ_DEVICE_CONTROL    0x0e
#define IO_HIDE_ADD_TARGET       0x4700
#define IO_HIDE_DEL_TARGET       0x4701
#define IO_HIDE_CHECK_TARGET     0x4702

#define IO_PROTECT_ADD_TARGET    0x4710
#define IO_PROTECT_DEL_TARGET    0x4711
#define IO_PROTECT_CHECK_TARGET  0x4712

#define IO_GET_PROCESSHANDLE     0x4720

#define IO_READ_PROCESS_MEMORY   0x4730
#define IO_WRITE_PROCESS_MEMORY  0x4731

typedef struct _DEVICE_EXTENSION
{
    ULONG StateVariable;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

typedef struct ServiceDescriptorTableExtry
{
	unsigned int* ServiceTableBase;
	unsigned int* ServiceCounterTableBase;
	unsigned int* NumberOfService;
	unsigned char* ParamTableBase;
}SSDT, *PSSDT;
extern PSSDT KeServiceDescriptorTable;

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
  
typedef struct _SYSTEM_PROCESSES   
{   
    ULONG NextEntryDelta;     
    ULONG ThreadCount;           
    ULONG Reserved[6];   
    LARGE_INTEGER CreateTime;       
    LARGE_INTEGER UserTime;            
    LARGE_INTEGER KernelTime;        
    UNICODE_STRING ProcessName; 
    KPRIORITY BasePriority;         
    ULONG ProcessId;                     
    ULONG InheritedFromProcessId;         
    ULONG HandleCount;             
    ULONG Reserved2[2];   
    VM_COUNTERS VmCounters;         
    IO_COUNTERS IoCounters;               
    struct _SYSTEM_THREADS Threads[1];  
}SystemProcessInformation, *PSystemProcessInformation;
///////////////////////////////////////////////////////////////////////////////
NTSYSAPI NTSTATUS NTAPI ZwOpenProcess(
  __out     PHANDLE ProcessHandle,
  __in      ACCESS_MASK DesiredAccess,
  __in      POBJECT_ATTRIBUTES ObjectAttributes,
  __in_opt  PCLIENT_ID ClientId
	);

typedef NTSTATUS (* NTOPENPROCESS)(
  __out     PHANDLE ProcessHandle,
  __in      ACCESS_MASK DesiredAccess,
  __in      POBJECT_ATTRIBUTES ObjectAttributes,
  __in_opt  PCLIENT_ID ClientId
	);

NTSTATUS MyNtOpenProcess(
  __out     PHANDLE ProcessHandle,
  __in      ACCESS_MASK DesiredAccess,
  __in      POBJECT_ATTRIBUTES ObjectAttributes,
  __in_opt  PCLIENT_ID ClientId
	);
///////////////////////////////////////////////////////////////////////////////
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
	IN ULONG SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength
	);

typedef NTSTATUS (* NTQUERYSYSTEMINFORMATION)(
	IN ULONG SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength
	);

NTSTATUS MyNtQuerySystemInformation(
	IN ULONG SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInforamtionLength,
	OUT PULONG ReturnLength
	);
/////////////////////////////////////////////////////////////
typedef NTSTATUS (* NTTERMINATEPROCESS)(
	IN HANDLE ProcessHandle,
	IN NTSTATUS ExitStatus
	);

NTSTATUS MyNtTerminateProcess(
	IN HANDLE ProcessHandle,
	IN NTSTATUS ExitStatus
	);
////////////////////////////////////////////////////////////
UCHAR * PsGetProcessImageFileName( 
                          __in PEPROCESS Process 
                          );

}


VOID Hook();
VOID UnHook();
VOID DriverUnLoad(IN PDRIVER_OBJECT DriverObject);

NTSTATUS DeviceIoControlDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS CreateDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS ReadDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS WriteDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS CloseDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS GeneralDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);

////////////////////////////////////////////////////////////////////////////////////////////////
BOOLEAN IsHidePId(IN ULONG lpPId);
NTSTATUS AddHidePIdList(IN ULONG lpPId);
ULONG FindHidePIdIndex(IN ULONG lpPId);
NTSTATUS DelHidePIdList(IN ULONG lpPId);
////////////////////////////////////////////////////////////////////////////////////////////////
BOOLEAN IsProtectPId(IN ULONG lpPId);
NTSTATUS AddProtectPIdList(IN ULONG lpPId);
ULONG FindProtectPIdIndex(IN ULONG lpPId);
NTSTATUS DelProtectPIdList(IN ULONG lpPId);
////////////////////////////////////////////////////////////////////////////////////////////////

ULONG NtQuerySystemInformationIndex = 0;
ULONG OldNtQuerySystemInformation = 0;
ULONG HidePId[1024], HidePIdLen = 0;

////////////////////////////////////////////////////////////////////////////////////////////////

ULONG NtOpenProcessIndex = 0;
ULONG OldNtOpenProcess = 0;
ULONG ProtectPId[1024], ProtectPIdLen = 0;

////////////////////////////////////////////////////////////////////////////////////////////////

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	KdPrint(("[MyDriver] Enter DriverEntry..."));
	Hook();
	KdPrint(("[MyDriver] SSDT Hook On!"));

	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING DeviceName,DosDeviceName;
	PDEVICE_OBJECT DeviceObject = NULL;
	ULONG i;

	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		DriverObject->MajorFunction[i] = GeneralDispatcher;
	}

	DriverObject->DriverUnload = DriverUnLoad;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateDispatcher;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CloseDispatcher;
	DriverObject->MajorFunction[IRP_MJ_READ] = ReadDispatcher;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = WriteDispatcher;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoControlDispatcher;

	KdPrint(("[MyDriver] DriverEntry: %wZ\n", RegistryPath));
	RtlInitUnicodeString(&DeviceName, MYDEVICE_DEVICE_NAME);
	//DeviceObject->Flags |= DO_BUFFERED_IO;
	status = IoCreateDevice(DriverObject, sizeof(DEVICE_EXTENSION), &DeviceName, FILE_DEVICE_UNKNOWN, 0, TRUE, &DeviceObject);
	if(!NT_SUCCESS(status))
	{
		KdPrint(("[MyDriver] IoCreateDevice Failed!"));
		return status;
	}
	RtlInitUnicodeString(&DosDeviceName, MYDEVICE_DOS_DEVICE_NAME);
	//DeviceObject->AlignmentRequirement = FILE_WORD_ALIGNMENT;
	status = IoCreateSymbolicLink(&DosDeviceName, &DeviceName);
	//DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
	if(!NT_SUCCESS(status))
	{
		KdPrint(("[MyDriver] IoSymbolicLink Failed!"));
		IoDeleteDevice(DeviceObject);
		return status;
	}
	
	return status;
}

VOID DriverUnLoad(IN PDRIVER_OBJECT DriverObject)
{
	UnHook();
	KdPrint(("[MyDriver] SSDT Hook Off!"));

	UNICODE_STRING dosDeviceName;

	RtlInitUnicodeString(&dosDeviceName, MYDEVICE_DOS_DEVICE_NAME);
	IoDeleteSymbolicLink(&dosDeviceName);
	IoDeleteDevice(DriverObject->DeviceObject);

	KdPrint(("[MyDriver] DriverUnLoad..."));
}

/*
Main Function
Function Name : Hook
*/
VOID Hook()
{
	NtQuerySystemInformationIndex = *(PULONG)((ULONG)ZwQuerySystemInformation + 1);
	OldNtQuerySystemInformation = KeServiceDescriptorTable->ServiceTableBase[NtQuerySystemInformationIndex];
	NtOpenProcessIndex = *(PULONG)((ULONG)ZwOpenProcess + 1);
	OldNtOpenProcess = KeServiceDescriptorTable->ServiceTableBase[NtOpenProcessIndex];
	__asm
	{
		cli
		mov eax,cr0
		and eax,not 10000h
	  //and eax,FFFEFFFFh
		mov cr0,eax
	}
	KeServiceDescriptorTable->ServiceTableBase[NtQuerySystemInformationIndex] = (ULONG)MyNtQuerySystemInformation;
	KeServiceDescriptorTable->ServiceTableBase[NtOpenProcessIndex] = (ULONG)MyNtOpenProcess;
	__asm
	{
		mov eax,cr0
		or eax,10000h
	  //or eax,not FFFEFFFFh
		mov cr0,eax
		sti
	}
}

VOID UnHook()
{
	__asm
	{
		cli
		mov eax,cr0
		and eax,not 10000h
		mov cr0,eax
	}
	KeServiceDescriptorTable->ServiceTableBase[NtQuerySystemInformationIndex] = OldNtQuerySystemInformation;
	KeServiceDescriptorTable->ServiceTableBase[NtOpenProcessIndex] = OldNtOpenProcess;
	__asm
	{
		mov eax,cr0
		or eax,10000h
		mov cr0,eax
		sti
	}
}

NTSTATUS MyNtOpenProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL
	)
{
	if(IsProtectPId((ULONG)ClientId->UniqueProcess) == FALSE)
	{
		NTSTATUS rtstatus = STATUS_SUCCESS;
		rtstatus = ((NTOPENPROCESS)OldNtOpenProcess)(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
		return rtstatus;
	}
	else
	{
		KdPrint(("[MyDriver]ProtectPId Success!"));
		return STATUS_ACCESS_DENIED;
	}
}

NTSTATUS MyNtQuerySystemInformation(
	IN ULONG SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength)
{
	NTSTATUS rtstatus = STATUS_SUCCESS;
	UNICODE_STRING TargetProcessName;

	rtstatus = ((NTQUERYSYSTEMINFORMATION)OldNtQuerySystemInformation)(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	if(NT_SUCCESS(rtstatus))
	{
		if(SystemInformationClass == 5)
		{
			PSystemProcessInformation CurrInfo = NULL;
			PSystemProcessInformation PrevInfo = NULL;
			CurrInfo = (PSystemProcessInformation)SystemInformation;

			//RtlInitUnicodeString(&TargetProcessName, L"notepad.exe");

			while(CurrInfo != NULL)
			{
				//if(RtlCompareUnicodeString(&TargetProcessName, &CurrInfo->ProcessName, TRUE) == 0)
				if(IsHidePId(CurrInfo->ProcessId) == TRUE)
				{
					if(PrevInfo)
					{
						if(CurrInfo->NextEntryDelta)
						{
							PrevInfo->NextEntryDelta += CurrInfo->NextEntryDelta;
							CurrInfo = (PSystemProcessInformation)((ULONG)CurrInfo + CurrInfo->NextEntryDelta);
						}
						else
						{
							PrevInfo->NextEntryDelta = 0;
						}
					}
					else
					{
						if(CurrInfo->NextEntryDelta)
						{
							ULONG FirstOffSet = ((PSystemProcessInformation)SystemInformation)->NextEntryDelta;
							CurrInfo = (PSystemProcessInformation)((ULONG)CurrInfo + CurrInfo->NextEntryDelta);
							memcpy(SystemInformation, CurrInfo, sizeof(SystemProcessInformation));
							((PSystemProcessInformation)SystemInformation)->NextEntryDelta += FirstOffSet;
						}
						else
						{
							memset(SystemInformation, 0, sizeof(SystemInformation));
							break;
						}
					}
				}
				else
				{
					PrevInfo = CurrInfo;
					if(PrevInfo->NextEntryDelta == 0)
						break;
					CurrInfo = (PSystemProcessInformation)((ULONG)CurrInfo + CurrInfo->NextEntryDelta);
				}
			}
		}
	}
	return rtstatus;
}

NTSTATUS DeviceIoControlDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	NTSTATUS rtstatus = STATUS_SUCCESS;
	ULONG PId = 0;
	ULONG InLen, OutLen;
	ULONG CtrlCode;
	ULONG_PTR information = 0;

	PCHAR InBuffer;

	KdPrint(("Call DeviceIoControl"));
	PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(pIrp);

	InLen = Stack->Parameters.DeviceIoControl.InputBufferLength;
	OutLen = Stack->Parameters.DeviceIoControl.OutputBufferLength;
	CtrlCode = Stack->Parameters.DeviceIoControl.IoControlCode;

	InBuffer = (PCHAR)pIrp->AssociatedIrp.SystemBuffer;

	if(InLen >= 4)
	{

		PId = atol(InBuffer);

		switch(CtrlCode)
		{
		case IO_HIDE_ADD_TARGET:
			{
				KdPrint(("PId : %d", PId));
				if(NT_SUCCESS(AddHidePIdList(PId)))
				{
					KdPrint(("ChangeTagetTo : %d  Success!", PId));
					rtstatus = STATUS_SUCCESS;
				}
				else
				{
					KdPrint(("ChangeTagetTo : %d  UnSuccessful!", PId));
					rtstatus = STATUS_UNSUCCESSFUL;
				}
				break;
			}
		case IO_HIDE_DEL_TARGET:
			{
				KdPrint(("PId : %d", PId));
				if(NT_SUCCESS(DelHidePIdList(PId)))
				{
					KdPrint(("Delete : %d  Success!", PId));
					rtstatus = STATUS_SUCCESS;
				}
				else
				{
					KdPrint(("Delete : %d  UnSuccessful!", PId));
					rtstatus = STATUS_UNSUCCESSFUL;
				}
				break;
			}
		case IO_HIDE_CHECK_TARGET:
			{
				if(NT_SUCCESS(IsHidePId(PId)))
					rtstatus = STATUS_SUCCESS;
				else
					rtstatus = STATUS_UNSUCCESSFUL;
				break;
			}
		case IO_PROTECT_ADD_TARGET:
			{
				KdPrint(("PId : %d", PId));
				if(NT_SUCCESS(AddProtectPIdList(PId)))
				{
					KdPrint(("ChangeTagetTo : %d  Success!", PId));
					rtstatus = STATUS_SUCCESS;
				}
				else
				{
					KdPrint(("ChangeTagetTo : %d  UnSuccessful!", PId));
					rtstatus = STATUS_UNSUCCESSFUL;
				}
				break;
			}
		case IO_PROTECT_DEL_TARGET:
			{
				KdPrint(("PId : %d", PId));
				if(NT_SUCCESS(DelProtectPIdList(PId)))
				{
					KdPrint(("Delete : %d  Success!", PId));
					rtstatus = STATUS_SUCCESS;
				}
				else
				{
					KdPrint(("Delete : %d  UnSuccessful!", PId));
					rtstatus = STATUS_UNSUCCESSFUL;
				}
				break;
			}
		case IO_PROTECT_CHECK_TARGET:
			{
				if(NT_SUCCESS(IsProtectPId(PId)))
					rtstatus = STATUS_SUCCESS;
				else
					rtstatus = STATUS_UNSUCCESSFUL;
				break;
			}
		case IO_GET_PROCESSHANDLE:
			{
				KdPrint(("PId : %d", PId));

				HANDLE ProcessHandle = 0; 
				NTSTATUS rtstatus = STATUS_SUCCESS;
				CLIENT_ID dwPId; 
				OBJECT_ATTRIBUTES ObjectAttributes;
				PVOID OutBuffer = 0;

				dwPId.UniqueProcess = LongToHandle(PId); dwPId.UniqueThread = LongToHandle(NULL);
				InitializeObjectAttributes(&ObjectAttributes, NULL, NULL, NULL, NULL);

				//ObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
				KdPrint(("OldNtOpenProcess Address : 0x%X", OldNtOpenProcess));
				KdPrint(("ZwOpenProcess Address : 0x%X", (ULONG)ZwOpenProcess));
				rtstatus = ZwOpenProcess(&ProcessHandle, (ACCESS_MASK)PROCESS_ALL_ACCESS, &ObjectAttributes, &dwPId);
				//rtstatus = ((NTOPENPROCESS)OldNtOpenProcess)(&ProcessHandle, (ACCESS_MASK)PROCESS_ALL_ACCESS, &ObjectAttributes, &dwPId);
				KdPrint(("ProcessHandle : %d & return : %d", (ULONG)HandleToULong(ProcessHandle), (ULONG)NT_SUCCESS(rtstatus)));
				//RtlCopyMemory(OutBuffer, (PVOID)HandleToULong(ProcessHandle), 4);
				pIrp->UserBuffer = (PVOID)HandleToULong(ProcessHandle);
				//InBuffer = (PCHAR)HandleToULong(ProcessHandle);
				//pIrp->AssociatedIrp.SystemBuffer = (PVOID)HandleToULong(ProcessHandle);
				information = 4;
				break;
			}
		default:
			{
				rtstatus = STATUS_INVALID_VARIANT;
				break;
			}
		}
	}
	else
	{
		rtstatus = STATUS_INVALID_PARAMETER;
	}
	pIrp->IoStatus.Status = rtstatus;
	pIrp->IoStatus.Information = information;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return rtstatus;
}

NTSTATUS GeneralDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return pIrp->IoStatus.Status;
}

NTSTATUS CloseDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS CreateDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	KdPrint(("Call IRP_MJ_CREATE"));
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS ReadDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	KdPrint(("Call IRP_MJ_READ"));

	NTSTATUS rtStatus;

	//rtStatus = STATUS_NOT_SUPPORTED;
	rtStatus = STATUS_SUCCESS;

	return rtStatus;
}

NTSTATUS WriteDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	NTSTATUS rtStatus;

	rtStatus = STATUS_NOT_SUPPORTED;

	return rtStatus;
}

BOOLEAN IsHidePId(IN ULONG lpPId)
{
	ULONG Counter;
	for(Counter = 0; Counter < HidePIdLen && Counter < 1024; Counter++)
	{
		if(HidePId[Counter] == lpPId)
		{
			return TRUE;
		}
	}
	return FALSE;
}

NTSTATUS AddHidePIdList(IN ULONG lpPId)
{
	KdPrint(("Call AddHidePIdList"));
	if(IsHidePId(lpPId) == FALSE)
	{
		KdPrint(("CheckPId Success!"));
		HidePId[HidePIdLen++] = lpPId;
		KdPrint(("HidePIdLen : %d", HidePIdLen));
		return STATUS_SUCCESS;
	}
	return STATUS_UNSUCCESSFUL;
}

ULONG FindHidePIdIndex(IN ULONG lpPId)
{
	ULONG Counter;
	for(Counter = 0; Counter < HidePIdLen && Counter < 1024; Counter++)
	{
		KdPrint(("Counter : %d , PId : %d", Counter, HidePId[Counter]));
		KdPrint(("lpPId : %d", lpPId));
		if(HidePId[Counter] == lpPId)
		{
			return Counter;
		}
	}
	return -1;
}

NTSTATUS DelHidePIdList(IN ULONG lpPId)
{
	KdPrint(("Call DelHidePIdList"));
	ULONG index = FindHidePIdIndex(lpPId);
	KdPrint(("Call FindPIdIndex, result : %d", index));
	if(index != -1)
	{
		KdPrint(("HidePId[HidePIdLen] is : %d", HidePId[HidePIdLen]));
		HidePId[index] = HidePId[--HidePIdLen];
		return STATUS_SUCCESS;
	}
	return STATUS_UNSUCCESSFUL;
}

BOOLEAN IsProtectPId(IN ULONG lpPId)
{
	ULONG Counter;
	for(Counter = 0; Counter < ProtectPIdLen && Counter < 1024; Counter++)
	{
		if(ProtectPId[Counter] == lpPId)
		{
			return TRUE;
		}
	}
	return FALSE;
}

NTSTATUS AddProtectPIdList(IN ULONG lpPId)
{
	KdPrint(("Call AddProtectPIdList"));
	if(IsProtectPId(lpPId) == FALSE)
	{
		KdPrint(("CheckPId Success!"));
		ProtectPId[ProtectPIdLen++] = lpPId;
		KdPrint(("ProtectPIdLen : %d", ProtectPIdLen));
		return STATUS_SUCCESS;
	}
	return STATUS_UNSUCCESSFUL;
}

ULONG FindProtectPIdIndex(IN ULONG lpPId)
{
	ULONG Counter;
	for(Counter = 0; Counter < ProtectPIdLen && Counter < 1024; Counter++)
	{
		KdPrint(("Counter : %d , PId : %d", Counter, ProtectPId[Counter]));
		KdPrint(("lpPId : %d", lpPId));
		if(ProtectPId[Counter] == lpPId)
		{
			return Counter;
		}
	}
	return -1;
}

NTSTATUS DelProtectPIdList(IN ULONG lpPId)
{
	KdPrint(("Call DelProtectPIdList"));
	ULONG index = FindProtectPIdIndex(lpPId);
	KdPrint(("Call FindPIdIndex, result : %d", index));
	if(index != -1)
	{
		KdPrint(("ProtectPId[ProtectPIdLen] is : %d", ProtectPId[ProtectPIdLen]));
		ProtectPId[index] = ProtectPId[--ProtectPIdLen];
		return STATUS_SUCCESS;
	}
	return STATUS_UNSUCCESSFUL;
}