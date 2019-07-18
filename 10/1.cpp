/*
#include "ntddk.h"

NTSTATUS MyAddDevice(IN PDRIVER_OBJECT,IN PDEVICE_OBJECT);

typedef struct _DEVICE_EXTENSION
{
    PDEVICE_OBJECT    fdo;
    PDEVICE_OBJECT    NextStackDevice;
    UNICODE_STRING    ifSymLinkName;

} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

extern "C" NTSTATUS 
	DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath) 
{
	UNICODE_STRING Name,DosName,NtName;NTSTATUS status;PDEVICE_OBJECT DeviceObject;
	RtlInitUnicodeString(&Name,L"LCK");
	status = IoCreateDevice(DriverObject,sizeof(DEVICE_EXTENSION),&Name,FILE_DEVICE_UNKNOWN,0,FALSE,&DeviceObject);
	if(!NT_SUCCESS(status))
		KdPrint(("[Test] IoCreateDevice Error Code = 0x%X\n",status));
		return status;
	PDEVICE_EXTENSION dx = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
	RtlInitUnicodeString(&DosName,L"TEST_DOS_DEVICE_NAME_W");
	status = IoCreateSymbolicLink(&DosName,&NtName);
	if(!NT_SUCCESS(status))
	{
		KdPrint(("[Test] IoCreateSymbolicLink Error Code=0x%X\n",status));
		IoDeleteDevice(DeviceObject);
		return status;
	}
	KdPrint(("[Test] Finish!"));
	IoDeleteSymbolicLink(&DosName);
	IoDeleteDevice(DriverObject->DeviceObject);
	KdPrint(("[Test] Unloaded"));
	return STATUS_SUCCESS; 
}
*/

/*
NTSTATUS MyAddDevice(IN PDRIVER_OBJECT DriverObject,IN PDEVICE_OBJECT PhysicalDeviceObject)
{
	dx->fdo = DeviceObject;
	dx->NextStackDevice = IoAttachDeviceToDeviceStack(DeviceObject,PhysicalDeviceObject);
	DeviceObject->Flags |= DO_BUFFERED_IO | DO_POWER_PAGABLE;
	DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
	return STATUS_SUCCESS;
}
*/

/*
NTSTATUS
	MyAddDevice(IN PDRIVER_OBJECT DriverObject,IN PDEVICE_OBJECT PhysicalDriverObject)
{
	NTSTATUS status;
	PDEVICE_OBJECT fdo;
	status = IoCreateDevice(DriverObject,sizeof(_DEVICE_OBJECT),NULL,FILE_DEVICE_UNKNOWN,0,FALSE,&fdo);
	if(!NT_SUCCESS(status))
		return status;
	fdo->NextDevice = IoAttachDeviceToDeviceStack(fdo,PhysicalDriverObject);
	fdo->Flags |= DO_BUFFERED_IO | DO_POWER_PAGABLE;
	fdo->Flags &= ~DO_DEVICE_INITIALIZING;
	return STATUS_SUCCESS;
}
*/