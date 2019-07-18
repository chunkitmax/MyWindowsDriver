/*#include "ntddk.h"

//extern"C" NTSTATUS __stdcall NtCloseHandle(HANDLE hObject);

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath)
{
	HANDLE hp;OBJECT_ATTRIBUTES oa = {sizeof(OBJECT_ATTRIBUTES),0,NULL,NULL};CLIENT_ID id;
	KdPrint(("Hello World!"));
	id.UniqueProcess = (HANDLE)2528;id.UniqueThread = (HANDLE)0;
	oa.Attributes = 0;
	NTSTATUS status = NtOpenProcess(&hp,PROCESS_ALL_ACCESS,&oa,&id);
	if(!NT_SUCCESS(status))
		KdPrint(("PID:2528, HANDLE:%u",hp));
	else
		KdPrint(("PID:2528, HANDLE:%x",status));
	KdPrint(("All Finish!"));
	return STATUS_SUCCESS;
}
*/