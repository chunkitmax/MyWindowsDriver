/*

此驅動程式是供文件保護之用
by PeterLau

*/
//#include <ntddk.h>
#include <stdlib.h>
#include <ntifs.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define MYDEVICE_DEVICE_NAME     L"\\Device\\MyDriver"
#define MYDEVICE_DOS_DEVICE_NAME L"\\??\\MyDriver"
#define  DELAY_ONE_MICROSECOND  (-10)
#define  DELAY_ONE_MILLISECOND (DELAY_ONE_MICROSECOND*1000)
#define  DELAY_ONE_SECOND (DELAY_ONE_MILLISECOND*1000)

/*
CTL_CODE(  
  DeviceType,  
  Function,  
  Method,  
  Access  
);  

參數說明 : 

* DeviceType : 裝置物件的類型, 這個類型應該和新建裝置 (IoCreateDevice) 時的類型相匹配. 一般是 FILE_DEVICE_XX 長相的巨集.
* Function : 這是驅動程式定義的 IOCTL 碼. 其中 :
- 0x0000 到 0x7FFF > 微軟保留
- 0x8000 到 0xFFFF > 程式設計師自己定義
* Method : 這示操作模式, 可已是下列四種模式之一
- METHOD_BUFFERED : 使用緩衝區方式操作
- METHOD_IN_DIRECT : 使用直接寫方式操作
- METHOD_OUT_DIRECT : 使用直接讀方式操作
- METHOD_NEITHER : 使用其他方式操作
* Access : 存取權限, 如果沒有特殊要求, 一般使用 FILE_ANY_ACCESS
*/

/////////////////////////////////////////////////////////

// 設備類型定義
// 0-32767被Microsoft佔用，用戶自定義可用32768-65535
//#define FILE_DEVICE_MYPORT 0x0000f000

/////////////////////////////////////////////////////////

// I/O控制碼定義
// 0x0000-0x07FF被Microsoft佔用，用戶自定義可用&H0800-&H0FFF 
#define IOCTL_BASE 0xE00

/////////////////////////////////////////////////////////
//					AddProtectFile					   //

#define NEW_TARGET_FILE						CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SET_LAST_TARGET_FILE_NAME			CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SET_LAST_TARGET_FILE_DEVICE_NAME	CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DEL_TARGET_FILE_BY_FILE_NAME		CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DEL_TARGET_FILE_BY_FILE_DEVICE_NAME	CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define NEW_TARGET_DECUMENT					CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 13, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SET_LAST_TARGET_DOCUMENT_DEVICE_NAME CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 14, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SET_LAST_TARGET_DOCUMENT_PATH		CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 15, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DEL_TARGET_DOCUMENT_BY_PATH			CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 16, METHOD_BUFFERED, FILE_ANY_ACCESS)

/////////////////////////////////////////////////////////
//					AddLockFile						   //

#define NEW_LOCK_FILE						CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SET_LAST_LOCK_FILE_FULL_PATH		CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DEL_LOCK_FILE_BY_FILE_FULL_PATH		CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define NEW_LOCK_DOCUMENT					CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 17, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SET_LAST_LOCK_DOCUMENT_FULL_PATH	CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 18, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DEL_LOCK_DOCUMENT_BY_FULL_PATH		CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 19, METHOD_BUFFERED, FILE_ANY_ACCESS)

/////////////////////////////////////////////////////////
//					AddDisableFile					   //

#define NEW_DISABLE_FILE					CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 8, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SET_LAST_DISABLE_FILE_NAME			CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 9, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SET_LAST_DISABLE_FILE_DEVICE_NAME	CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 10, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DEL_DISABLE_FILE_BY_FILE_NAME		CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 11, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DEL_DISABLE_FILE_BY_FILE_DEVICE_NAME CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 12, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define NEW_DISABLE_DOCUMENT				CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 20, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SET_LAST_DISABLE_DOCUMENT_DEVICE_NAME CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 21, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SET_LAST_DISABLE_DOCUMENT_PATH		CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 22, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DEL_DISABLE_DOCUMENT_BY_PATH		CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 23, METHOD_BUFFERED, FILE_ANY_ACCESS)

/////////////////////////////////////////////////////////
//					UnHookSSDT						   //

#define SSDT_HOOK							CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 24, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SSDT_UNHOOK							CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 25, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SSDT_INIT							CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 26, METHOD_BUFFERED, FILE_ANY_ACCESS)

/////////////////////////////////////////////////////////

typedef struct _DEVICE_EXTENSION
{
    ULONG StateVariable;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

typedef struct ServiceDescriptorTableEntry
{
	unsigned int* ServiceTableBase;
	unsigned int* ServiceCounterTableBase;
	unsigned int* NumberOfService;
	unsigned char* ParamTableBase;
}SSDT, *PSSDT;
extern PSSDT KeServiceDescriptorTable;

/////////////////////////////////////////////////////////////

typedef NTSTATUS (*NTSETINFORMATIONFILE)
	(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass
	);

NTSTATUS MyNtSetInformationFile
	(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass
	);

//////////////////////////////////////////////////////////////

typedef NTSTATUS (*NTCREATEFILE)
	(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER AllocationSize OPTIONAL,
	IN ULONG FileAttributes,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN PVOID EaBuffer OPTIONAL,
	IN ULONG EaLength
	);

NTSTATUS MyNtCreateFile
	(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER AllocationSize OPTIONAL,
	IN ULONG FileAttributes,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN PVOID EaBuffer OPTIONAL,
	IN ULONG EaLength
	);

//////////////////////////////////////////////////////////////

typedef NTSTATUS (*NTOPENFILE)
	(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess,
	IN ULONG OpenOptions
	);

NTSTATUS MyNtOpenFile
	(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess,
	IN ULONG OpenOptions
	);

////////////////////////////////////////////////////////////

typedef NTSTATUS (*NTREADFILE)
	(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN PULONG Key OPTIONAL
	);

NTSTATUS MyNtReadFile
	(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN PULONG Key OPTIONAL
	);

////////////////////////////////////////////////////////////

typedef NTSTATUS (*NTWRITEFILE)
	(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN PULONG Key OPTIONAL
	);

NTSTATUS MyNtWriteFile
	(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN PULONG Key OPTIONAL
	);

////////////////////////////////////////////////////////////

NTSYSAPI NTSTATUS NTAPI ZwDeleteFile
	(
	IN POBJECT_ATTRIBUTES ObjectAttributes
	);

typedef NTSTATUS (*NTDELETEFILE)
	(
	IN POBJECT_ATTRIBUTES ObjectAttributes
	);

NTSTATUS MyNtDeleteFile
	(
	IN POBJECT_ATTRIBUTES ObjectAttributes
	);

////////////////////////////////////////////////////////////

}

VOID InitHook();
VOID Hook();
VOID UnHook();
VOID DriverUnLoad(IN PDRIVER_OBJECT DriverObject);
NTSTATUS IsProtectedFile(IN HANDLE FileHandle);
NTSTATUS IsLockedFile(IN PUNICODE_STRING FilePath);
NTSTATUS IsDisableFile(IN HANDLE FileHandle);

NTSTATUS DeviceIoControlDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS CreateDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS ReadDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS WriteDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS CloseDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS GeneralDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);

////////////////////////////////////////////////////////////////////////////////////////////////

ULONG NtSetInformationFileIndex = 0;
ULONG OldSetInformationFile = 0;
ULONG NtDeleteFileIndex = 0;
ULONG OldNtDeleteFile = 0;
UNICODE_STRING TargetFileName[1024];
UNICODE_STRING TargetFileDeviceName[1024];
UNICODE_STRING TargetDocumentDeviceName[1024];
UNICODE_STRING TargetDocumentPath[1024];
ULONG TargetFileInformationLen = 0;
ULONG TargetDocumentInformationLen = 0;
BOOLEAN TargetFileInformationDeleting = FALSE;
BOOLEAN TargetDocumentInformationDeleting = FALSE;

////////////////////////////////////////////////////////////////////////////////////////////////

ULONG NtCreateFileIndex = 0;
ULONG OldNtCreateFile = 0;
ULONG NtOpenFileIndex = 0;
ULONG OldNtOpenFile = 0;
UNICODE_STRING LockedFileFullPath[1024];
UNICODE_STRING LockedDocumentFullPath[1024];
ULONG LockedFileInformationLen = 0;
ULONG LockedDocumentInformationLen = 0;
BOOLEAN LockedFileInformationDeleting = FALSE;
BOOLEAN LockedDocumentInformationDeleting = FALSE;

////////////////////////////////////////////////////////////////////////////////////////////////

ULONG NtReadFileIndex = 0;
ULONG OldNtReadFile = 0;
ULONG NtWriteFileIndex = 0;
ULONG OldNtWriteFile = 0;
UNICODE_STRING DisableFileName[1024];
UNICODE_STRING DisableFileDeviceName[1024];
UNICODE_STRING DisableDocumentDeviceName[1024];
UNICODE_STRING DisableDocumentPath[1024];
ULONG DisableFileInformationLen = 0;
ULONG DisableDocumentInformationLen = 0;
BOOLEAN DisableFileInformationDeleting = FALSE;
BOOLEAN DisableDocumentInformationDeleting = FALSE;
////////////////////////////////////////////////////////////////////////////////////////////////

BOOLEAN IsInit = FALSE;

////////////////////////////////////////////////////////////////////////////////////////////////

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	KdPrint(("[MyDriver] Enter DriverEntry..."));
	/*Hook();
	KdPrint(("[MyDriver] SSDT Hook On!"));
	*/
	InitHook();
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

	/*
	RtlInitUnicodeString(&LockedFileFullPath[0], L"\\??\\C:\\b.bat");
	LockedFileInformationLen++;
	*/
	//UNICODE_STRING NtDllName;
	//RtlInitUnicodeString(&NtDllName, L"\\Device\\HarddiskVolume1\\Windows\\System32\\ntdll.dll");

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
	KdPrint(("[MyDriver] SSDT Hook Off!"));
	UnHook();
	/*
	ULONG RetryCount = 0;
	LARGE_INTEGER Delay;
	Delay = RtlConvertLongToLargeInteger(100 * DELAY_ONE_MILLISECOND);
	*/
	KdPrint(("[MyDriver] DriverUnLoad..."));
	/*
ReCheck:
	KdPrint(("IRPCount : %d && DeleteCount : %d && ReadWriteCount : %d && CreateOpenCount : %d", IRPCount, DeleteCount, ReadWriteCount, CreateOpenCount));
	while (IRPCount > 0 && IRPCount > 0 && DeleteCount > 0 && ReadWriteCount > 0 && CreateOpenCount > 0 && RetryCount <= 150)
	{
		KeDelayExecutionThread(KernelMode, FALSE, &Delay);
		KdPrint(("Waiting For Irps And API , IRPCount : %d && DeleteCount : %d && ReadWriteCount : %d && CreateOpenCount : %d, RetryCountDown : %d",  IRPCount, DeleteCount, ReadWriteCount, CreateOpenCount, (ULONG)(150 - RetryCount)));
		RetryCount++;
	}
	*/
	/*ULONG TotalDevice = 0;
	IoEnumerateDeviceObjectList(DriverObject, NULL, 0, &TotalDevice);
	KdPrint(("TotalDevice : %d", TotalDevice));
	*/
	/*
	Delay = RtlConvertLongToLargeInteger(5 * DELAY_ONE_SECOND);
	KeDelayExecutionThread(KernelMode, FALSE, &Delay);
	*/
	UNICODE_STRING dosDeviceName;
	RtlInitUnicodeString(&dosDeviceName, MYDEVICE_DOS_DEVICE_NAME);
	IoDeleteSymbolicLink(&dosDeviceName);
	IoDeleteDevice(DriverObject->DeviceObject);
}
/*
Init Fnction
Function Name : InitHook
*/
VOID InitHook()
{
	if(IsInit)
		return;
	NtSetInformationFileIndex = *(PULONG)((ULONG)ZwSetInformationFile + 1);
	OldSetInformationFile = KeServiceDescriptorTable->ServiceTableBase[NtSetInformationFileIndex];
	NtDeleteFileIndex = *(PULONG)((ULONG)ZwDeleteFile + 1);
	OldNtDeleteFile = KeServiceDescriptorTable->ServiceTableBase[NtDeleteFileIndex];
	NtCreateFileIndex = *(PULONG)((ULONG)ZwCreateFile + 1);
	OldNtCreateFile = KeServiceDescriptorTable->ServiceTableBase[NtCreateFileIndex];
	NtOpenFileIndex = *(PULONG)((ULONG)ZwOpenFile + 1);
	OldNtOpenFile = KeServiceDescriptorTable->ServiceTableBase[NtOpenFileIndex];
	NtReadFileIndex = *(PULONG)((ULONG)ZwReadFile + 1);
	OldNtReadFile = KeServiceDescriptorTable->ServiceTableBase[NtReadFileIndex];
	NtWriteFileIndex = *(PULONG)((ULONG)ZwWriteFile + 1);
	OldNtWriteFile = KeServiceDescriptorTable->ServiceTableBase[NtWriteFileIndex];
	IsInit = TRUE;
}
/*
Main Function
Function Name : Hook
*/
VOID Hook()
{
	if(!IsInit)
		InitHook();
	__asm
	{
		cli
		mov eax,cr0
		and eax,not 10000h
	  //and eax,FFFEFFFFh
		mov cr0,eax
	}
	KeServiceDescriptorTable->ServiceTableBase[NtSetInformationFileIndex] = (ULONG)MyNtSetInformationFile;
	KeServiceDescriptorTable->ServiceTableBase[NtDeleteFileIndex] = (ULONG)MyNtDeleteFile;
	KeServiceDescriptorTable->ServiceTableBase[NtCreateFileIndex] = (ULONG)MyNtCreateFile;
	KeServiceDescriptorTable->ServiceTableBase[NtOpenFileIndex] = (ULONG)MyNtOpenFile;
	KeServiceDescriptorTable->ServiceTableBase[NtReadFileIndex] = (ULONG)MyNtReadFile;
	KeServiceDescriptorTable->ServiceTableBase[NtWriteFileIndex] = (ULONG)MyNtWriteFile;
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
	KeServiceDescriptorTable->ServiceTableBase[NtSetInformationFileIndex] = OldSetInformationFile;
	KeServiceDescriptorTable->ServiceTableBase[NtDeleteFileIndex] = OldNtDeleteFile;
	KeServiceDescriptorTable->ServiceTableBase[NtCreateFileIndex] = OldNtCreateFile;
	KeServiceDescriptorTable->ServiceTableBase[NtOpenFileIndex] = OldNtOpenFile;
	KeServiceDescriptorTable->ServiceTableBase[NtReadFileIndex] = OldNtReadFile;
	KeServiceDescriptorTable->ServiceTableBase[NtWriteFileIndex] = OldNtWriteFile;
	__asm
	{
		mov eax,cr0
		or eax,10000h
		mov cr0,eax
		sti
	}
}

NTSTATUS IsProtectedFile(IN HANDLE FileHandle)
{
	PFILE_OBJECT pFileObject;
	NTSTATUS rtstatus = ObReferenceObjectByHandle(FileHandle, GENERIC_READ, *IoFileObjectType, KernelMode, (PVOID*)&pFileObject, 0);
	if(NT_SUCCESS(rtstatus))
	{
		UNICODE_STRING uDosName;
		rtstatus = IoVolumeDeviceToDosName(pFileObject->DeviceObject, &uDosName);
		if(NT_SUCCESS(rtstatus))
		{
			if(TargetFileInformationLen != 0)
			{
				KdPrint(("FilePath : %S%S", uDosName.Buffer, pFileObject->FileName.Buffer));
DeletingPoint_a:
				while (TargetFileInformationDeleting == TRUE)
					KdPrint(("TargetFileInformationDeleting : %d", TargetFileInformationDeleting));
				for(int i = 0; i < TargetFileInformationLen; i++)
				{
					if(TargetFileInformationDeleting == TRUE) {goto DeletingPoint_a;}
					if(RtlEqualUnicodeString(&pFileObject->FileName, &TargetFileName[i], TRUE) && RtlEqualUnicodeString(&uDosName, &TargetFileDeviceName[i], TRUE))
					{
						//KdPrint(("First Condition : %d , Second Condition : %d", RtlEqualUnicodeString(&pFileObject->FileName, &TargetFileName[i], TRUE), RtlEqualUnicodeString(&uDosName, &TargetFileDeviceName[i], TRUE)));
						ExFreePool(uDosName.Buffer);
						return STATUS_SUCCESS;
					}
				}
			}
			if(TargetDocumentInformationLen != 0)
			{
DeletingPoint_b:
				while (TargetDocumentInformationDeleting == TRUE)
					KdPrint(("TargetDocumentInformationDeleting : %d", TargetDocumentInformationDeleting));
				for(int ii = 0; ii < TargetDocumentInformationLen; ii++)
				{
					if(TargetDocumentInformationDeleting == TRUE) {goto DeletingPoint_b;}
					if(RtlEqualUnicodeString(&TargetDocumentDeviceName[ii], &uDosName, TRUE) && RtlPrefixUnicodeString(&TargetDocumentPath[ii], &pFileObject->FileName, TRUE))
					{
						ExFreePool(uDosName.Buffer);
						return STATUS_SUCCESS;
					}
					/*
					KdPrint(("TargetDocumentDeviceName[ii] : %S , uDosName : %S", TargetDocumentDeviceName[ii].Buffer, uDosName.Buffer));
					KdPrint(("TargetDocumentPath[ii] : %S , pFileObject->FileName : %S", TargetDocumentPath[ii].Buffer, pFileObject->FileName.Buffer));
					KdPrint(("FCondition : %d , SCondition : %d", RtlEqualUnicodeString(&TargetDocumentDeviceName[ii], &uDosName, TRUE), RtlPrefixUnicodeString(&TargetDocumentPath[ii], &pFileObject->FileName, TRUE)));
					*/
				}
			}
		}
	}
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS MyNtSetInformationFile
	(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass
	)
{
	NTSTATUS rtstatus;

	if(NT_SUCCESS(IsProtectedFile(FileHandle)))
		rtstatus = STATUS_UNSUCCESSFUL;
	else
		rtstatus = ((NTSETINFORMATIONFILE)OldSetInformationFile)(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
	return rtstatus;
}

NTSTATUS IsTargetFile_FullPath(IN PUNICODE_STRING FilePath)
{
	KdPrint(("NtDeleteFile Target : %S", FilePath->Buffer));
	if(TargetFileInformationLen != 0)
	{
DeletingPoint_a:
		while (TargetFileInformationDeleting == TRUE)
			KdPrint(("TargetFileInformationDeleting : %d", TargetFileInformationDeleting));
		for(int i = 0; i < TargetFileInformationLen; i++)
		{
			UNICODE_STRING lString; RtlInitUnicodeString(&lString, L"\\??\\");
			if(TargetFileInformationDeleting == TRUE) {goto DeletingPoint_a;}
			RtlAppendUnicodeStringToString(&lString, &TargetFileDeviceName[i]); RtlAppendUnicodeStringToString(&lString, &TargetFileName[i]);
			if(RtlEqualUnicodeString(FilePath, &lString, TRUE))
			{
				//KdPrint(("Restult : %d", RtlEqualUnicodeString(FilePath, &TargetFileFullPath[i], TRUE)));
				return STATUS_SUCCESS;
			}
		}
	}
	if(TargetDocumentInformationLen != 0)
	{
DeletingPoint_b:
		while (TargetDocumentInformationDeleting == TRUE)
			KdPrint(("TargetDocumentInformationDeleting : %d", TargetDocumentInformationDeleting));
		for(int ii = 0; ii < TargetDocumentInformationLen; ii++)
		{
			UNICODE_STRING lString; RtlInitUnicodeString(&lString, L"\\??\\");
			if(TargetDocumentInformationDeleting == TRUE) {goto DeletingPoint_b;}
			RtlAppendUnicodeStringToString(&lString, &TargetDocumentDeviceName[ii]); RtlAppendUnicodeStringToString(&lString, &TargetDocumentPath[ii]);
			if(RtlPrefixUnicodeString(&lString, FilePath, TRUE))
			{
				//KdPrint(("Restult : %d", RtlEqualUnicodeString(FilePath, &TargetDocumentFullPath[i], TRUE)));
				return STATUS_SUCCESS;
			}
		}
	}
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS MyNtDeleteFile
	(
	IN POBJECT_ATTRIBUTES ObjectAttributes
	)
{
	NTSTATUS rtstatus;

	KdPrint(("NtDeleteFile Called !"));
	if(NT_SUCCESS(IsTargetFile_FullPath(ObjectAttributes->ObjectName)))
		rtstatus = STATUS_UNSUCCESSFUL;
	else
		rtstatus = ((NTDELETEFILE)OldNtDeleteFile)(ObjectAttributes);
	return rtstatus;
}

NTSTATUS IsLockedFile(IN PUNICODE_STRING FilePath)
{
	if(LockedFileInformationLen != 0)
	{
DeletingPoint_a:
		while (LockedFileInformationDeleting == TRUE)
			KdPrint(("LockedFileInformationDeleting : %d", LockedFileInformationDeleting));
		for(int i = 0; i < LockedFileInformationLen; i++)
		{
			if(LockedFileInformationDeleting == TRUE) {goto DeletingPoint_a;}
			if(RtlEqualUnicodeString(FilePath, &LockedFileFullPath[i], TRUE))
			{
				//KdPrint(("Restult : %d", RtlEqualUnicodeString(FilePath, &LockedFileFullPath[i], TRUE)));
				return STATUS_SUCCESS;
			}
		}
	}
	if(LockedDocumentInformationLen != 0)
	{
DeletingPoint_b:
		while (LockedDocumentInformationDeleting == TRUE)
			KdPrint(("LockedDocumentInformationDeleting : %d", LockedDocumentInformationDeleting));
		for(int ii = 0; ii < LockedDocumentInformationLen; ii++)
		{
			if(LockedDocumentInformationDeleting == TRUE) {goto DeletingPoint_b;}
			if(RtlPrefixUnicodeString(&LockedDocumentFullPath[ii], FilePath, TRUE))
			{
				//KdPrint(("Restult : %d", RtlEqualUnicodeString(FilePath, &LockedFileFullPath[i], TRUE)));
				return STATUS_SUCCESS;
			}
		}
	}
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS MyNtCreateFile
	(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER AllocationSize OPTIONAL,
	IN ULONG FileAttributes,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN PVOID EaBuffer OPTIONAL,
	IN ULONG EaLength
	)
{
	NTSTATUS rtstatus;

	if(NT_SUCCESS(IsLockedFile(ObjectAttributes->ObjectName)))
		rtstatus = STATUS_ACCESS_DENIED;
	else
		rtstatus = ((NTCREATEFILE)OldNtCreateFile)(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	return rtstatus;
}

NTSTATUS MyNtOpenFile
	(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess,
	IN ULONG OpenOptions
	)
{
	NTSTATUS rtstatus;

	if(NT_SUCCESS(IsLockedFile(ObjectAttributes->ObjectName)))
		rtstatus = STATUS_ACCESS_DENIED;
	else
		rtstatus = ((NTOPENFILE)OldNtOpenFile)(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
	return rtstatus;
}

NTSTATUS IsDisableFile(IN HANDLE FileHandle)
{
	PFILE_OBJECT pFileObject;
	NTSTATUS rtstatus = ObReferenceObjectByHandle(FileHandle, GENERIC_READ, *IoFileObjectType, KernelMode, (PVOID*)&pFileObject, 0);
	if(NT_SUCCESS(rtstatus))
	{
		UNICODE_STRING uDosName;
		rtstatus = IoVolumeDeviceToDosName(pFileObject->DeviceObject, &uDosName);
		if(NT_SUCCESS(rtstatus))
		{
			if(DisableFileInformationLen != 0)
			{
				KdPrint(("FilePath : %S%S", uDosName.Buffer, pFileObject->FileName.Buffer));
DeletingPoint_a:
				while (DisableFileInformationDeleting == TRUE)
					KdPrint(("DisableFileInformationDeleting : %d", DisableFileInformationDeleting));
				for(int i = 0; i < DisableFileInformationLen; i++)
				{
					if(DisableFileInformationDeleting == TRUE) {goto DeletingPoint_a;}
					if(RtlEqualUnicodeString(&pFileObject->FileName, &DisableFileName[i], TRUE) && RtlEqualUnicodeString(&uDosName, &DisableFileDeviceName[i], TRUE))
					{
						KdPrint(("First Condition : %d , Second Condition : %d", RtlEqualUnicodeString(&pFileObject->FileName, &DisableFileName[i], TRUE), RtlEqualUnicodeString(&uDosName, &DisableFileDeviceName[i], TRUE)));
						ExFreePool(uDosName.Buffer);
						return STATUS_SUCCESS;
					}
				}
			}
			if(DisableDocumentInformationLen != 0)
			{
DeletingPoint_b:
				while (DisableDocumentInformationDeleting == TRUE)
					KdPrint(("DisableDocumentInformationDeleting : %d", DisableDocumentInformationDeleting));
				for(int ii = 0; ii < DisableDocumentInformationLen; ii++)
				{
					if(DisableDocumentInformationDeleting == TRUE) {goto DeletingPoint_b;}
					if(RtlEqualUnicodeString(&DisableDocumentDeviceName[ii], &uDosName, TRUE) && RtlPrefixUnicodeString(&DisableDocumentPath[ii], &pFileObject->FileName, TRUE))
					{
						ExFreePool(uDosName.Buffer);
						return STATUS_SUCCESS;
					}
				}
			}
		}
	}
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS MyNtReadFile
	(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN PULONG Key OPTIONAL
	)
{
	NTSTATUS rtstatus;

	if(NT_SUCCESS(IsDisableFile(FileHandle)))
		rtstatus = STATUS_UNSUCCESSFUL;
	else
		rtstatus = ((NTREADFILE)OldNtReadFile)(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
	return rtstatus;
}

NTSTATUS MyNtWriteFile
	(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN PULONG Key OPTIONAL
	)
{
	NTSTATUS rtstatus;

	if(NT_SUCCESS(IsDisableFile(FileHandle)))
		rtstatus = STATUS_UNSUCCESSFUL;
	else
		rtstatus = ((NTWRITEFILE)OldNtWriteFile)(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
	return rtstatus;
}

NTSTATUS DeviceIoControlDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{

	NTSTATUS rtstatus = STATUS_SUCCESS;
	ULONG PId = 0;
	ULONG InLen, OutLen;
	ULONG CtrlCode;
	ANSI_STRING InBuffer;

	KdPrint(("->DeviceIoControl"));
	PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(pIrp);

	InLen = Stack->Parameters.DeviceIoControl.InputBufferLength;
	OutLen = Stack->Parameters.DeviceIoControl.OutputBufferLength;
	CtrlCode = Stack->Parameters.DeviceIoControl.IoControlCode;

	//InBuffer = (PCWSTR)pIrp->AssociatedIrp.SystemBuffer;

	RtlInitAnsiString (&InBuffer, (PCHAR)pIrp->AssociatedIrp.SystemBuffer);
	//PId = atol(InBuffer);
	//int RegionSize = mbstowcs(text, InBuffer, sizeof(InBuffer) + 1);
	//_itow(InBuffer, text, 10);

	KdPrint(("->DeviceIoControl->ControlCode : %d", CtrlCode));

	switch(CtrlCode)
	{
	case SSDT_INIT:{ InitHook(); KdPrint(("[MyDriver] SSDT Hook Init...")); break;}
	case SSDT_HOOK:{ Hook(); KdPrint(("[MyDriver] SSDT Hook On!")); break; }
	case SSDT_UNHOOK:
		{
			UnHook(); KdPrint(("[MyDriver] SSDT Hook Off!"));
			TargetFileInformationLen = 0; TargetDocumentInformationLen = 0;
			LockedFileInformationLen = 0; LockedDocumentInformationLen = 0;
			DisableFileInformationLen = 0; DisableDocumentInformationLen = 0;
			break;
		}
	case NEW_TARGET_FILE:
		{
			if(TargetFileName[TargetFileInformationLen].Length != 0 && TargetFileDeviceName[TargetFileInformationLen].Length != 0)
				KdPrint(("TargetFileInformationLen : %d", ++TargetFileInformationLen));
			else
				KdPrint(("TargetFileInformationLen : %d", TargetFileInformationLen));
			break;
		}
	case SET_LAST_TARGET_FILE_NAME:
		{
			
			/*
			size_t OrigStrSize = (strlen(InBuffer) + 1) * 2;
			//const size_t NewStrSize = 100;
			size_t RetStrSize = 0;
			wchar_t* text = new wchar_t[OrigStrSize];
			mbstowcs_s(&RetStrSize, text, OrigStrSize, InBuffer, _TRUNCATE);
			*/
			/*wchar_t szwBuffer[128];
			mbstowcs(szwBuffer, InBuffer, 128);*/
			
			//TargetFileName = Text;
			KdPrint(("CHANGESTRING : %d", RtlAnsiStringToUnicodeString(&TargetFileName[TargetFileInformationLen], &InBuffer, TRUE)));
			//TargetFileName = text;
			//KdPrint(("ChangeTargetFileTo : %wc", text));
			KdPrint(("ChangeLastTargetFileNameTo : %S", TargetFileName[TargetFileInformationLen].Buffer));
			//RtlFreeUnicodeString(&Text);
			rtstatus = STATUS_SUCCESS;
			break;
		}
	case SET_LAST_TARGET_FILE_DEVICE_NAME:
		{
			RtlAnsiStringToUnicodeString(&TargetFileDeviceName[TargetFileInformationLen], &InBuffer, TRUE);
			KdPrint(("ChangeLastTargetFileDeviceNameTo : %S", TargetFileDeviceName[TargetFileInformationLen].Buffer));
			break;
		}
	case DEL_TARGET_FILE_BY_FILE_NAME:
		{
			if(TargetFileInformationLen != 0)
			{

				TargetFileInformationDeleting = TRUE;
				
				UNICODE_STRING DelFileString;
				RtlAnsiStringToUnicodeString(&DelFileString, &InBuffer, TRUE);
				KdPrint(("DelFileString : %S", DelFileString.Buffer));
				int CurrentIndex = 0;
				for(int i = 0; i < TargetFileInformationLen; i++)
				{
					if(!RtlEqualUnicodeString(&DelFileString, &TargetFileName[i], TRUE))
					{
						TargetFileName[CurrentIndex] = TargetFileName[i];
						TargetFileDeviceName[CurrentIndex++] = TargetFileDeviceName[i];
					}
				}
				TargetFileInformationLen = (ULONG)CurrentIndex;
			}

			TargetFileInformationDeleting = FALSE;

			KdPrint(("New TargetFileInformationLen : %d", TargetFileInformationLen));
			break;
		}
	case DEL_TARGET_FILE_BY_FILE_DEVICE_NAME:
		{
			if(TargetFileInformationLen != 0)
			{

				TargetFileInformationDeleting = TRUE;

				UNICODE_STRING DelFileDeviceString;
				RtlAnsiStringToUnicodeString(&DelFileDeviceString, &InBuffer, TRUE);
				int CurrentIndex = 0;
				for(int i = 0; i < TargetFileInformationLen; i++)
				{
					if(!RtlEqualUnicodeString(&DelFileDeviceString, &TargetFileDeviceName[i], TRUE))
					{
						TargetFileName[CurrentIndex] = TargetFileName[i];
						TargetFileDeviceName[CurrentIndex++] = TargetFileDeviceName[i];
					}
				}
				TargetFileInformationLen = (ULONG)CurrentIndex;
			}

			TargetFileInformationDeleting = FALSE;

			KdPrint(("New TargetFileInformationLen : %d", TargetFileInformationLen));
			break;
		}
	case NEW_TARGET_DECUMENT:
		{
			if(TargetDocumentPath[TargetDocumentInformationLen].Length != 0 && TargetDocumentDeviceName[TargetDocumentInformationLen].Length != 0)
				KdPrint(("TargetDocumentInformationLen : %d", ++TargetDocumentInformationLen));
			else
				KdPrint(("TargetDocumentInformationLen : %d", TargetDocumentInformationLen));
			break;
		}
	case SET_LAST_TARGET_DOCUMENT_DEVICE_NAME:
		{
			RtlAnsiStringToUnicodeString(&TargetDocumentDeviceName[TargetDocumentInformationLen], &InBuffer, TRUE);
			KdPrint(("ChangeLastTargetDocumentDeviceNameTo : %S", TargetDocumentDeviceName[TargetDocumentInformationLen].Buffer));
			break;
		}
	case SET_LAST_TARGET_DOCUMENT_PATH:
		{
			RtlAnsiStringToUnicodeString(&TargetDocumentPath[TargetDocumentInformationLen], &InBuffer, TRUE);
			KdPrint(("ChangeLastTargetDocumentPathTo : %S", TargetDocumentPath[TargetDocumentInformationLen].Buffer));
			break;
		}
	case DEL_TARGET_DOCUMENT_BY_PATH:
		{
			if(TargetDocumentInformationLen != 0)
			{

				TargetDocumentInformationDeleting = TRUE;
				
				UNICODE_STRING DelFileString;
				RtlAnsiStringToUnicodeString(&DelFileString, &InBuffer, TRUE);
				KdPrint(("DelFileString : %S", DelFileString.Buffer));
				int CurrentIndex = 0;
				for(int i = 0; i < TargetDocumentInformationLen; i++)
				{
					if(!RtlEqualUnicodeString(&DelFileString, &TargetDocumentPath[i], TRUE))
					{
						TargetDocumentPath[CurrentIndex++] = TargetDocumentPath[i];
					}
				}
				TargetDocumentInformationLen = (ULONG)CurrentIndex;
			}

			TargetDocumentInformationDeleting = FALSE;

			KdPrint(("New TargetDocumentInformationLen : %d", TargetDocumentInformationLen));
			break;
		}
	case NEW_LOCK_FILE:
		{
			if(LockedFileFullPath[LockedFileInformationLen].Length != 0)
				KdPrint(("LockedFileInformationLen : %d", ++LockedFileInformationLen));
			else
				KdPrint(("LockedFileInformationLen : %d", LockedFileInformationLen));
			break;
		}
	case SET_LAST_LOCK_FILE_FULL_PATH:
		{
			RtlAnsiStringToUnicodeString(&LockedFileFullPath[LockedFileInformationLen], &InBuffer, TRUE);
			KdPrint(("ChangeLastLockFileFullPathTo : %S", LockedFileFullPath[LockedFileInformationLen].Buffer));
			break;
		}
	case DEL_LOCK_FILE_BY_FILE_FULL_PATH:
		{
			if(LockedFileInformationLen != 0)
			{

				LockedFileInformationDeleting = TRUE;

				UNICODE_STRING CompareString;
				RtlAnsiStringToUnicodeString(&CompareString, &InBuffer, TRUE);
				int CurrentIndex = 0;
				for(int i = 0; i < LockedFileInformationLen; i++)
				{
					if(!RtlEqualUnicodeString(&CompareString, &LockedFileFullPath[i], TRUE))
					{
						LockedFileFullPath[CurrentIndex++] = LockedFileFullPath[i];
					}
				}
				LockedFileInformationLen = (ULONG)CurrentIndex;
			}

			LockedFileInformationDeleting = FALSE;

			KdPrint(("New LockedFileInformationLen : %d", LockedFileInformationLen));
			break;
		}
	case NEW_LOCK_DOCUMENT:
		{
			if(LockedDocumentFullPath[LockedDocumentInformationLen].Length != 0)
				KdPrint(("LockedDocumentInformationLen : %d", ++LockedDocumentInformationLen));
			else
				KdPrint(("LockedDocumentInformationLen : %d", LockedDocumentInformationLen));
			break;
		}
	case SET_LAST_LOCK_DOCUMENT_FULL_PATH:
		{
			RtlAnsiStringToUnicodeString(&LockedDocumentFullPath[LockedDocumentInformationLen], &InBuffer, TRUE);
			KdPrint(("ChangeLastLockedDocumentFullPath : %S", LockedDocumentFullPath[LockedDocumentInformationLen].Buffer));
			break;
		}
	case DEL_LOCK_DOCUMENT_BY_FULL_PATH:
		{
			if(LockedDocumentInformationLen != 0)
			{

				LockedDocumentInformationDeleting = TRUE;
				
				UNICODE_STRING DelFileString;
				RtlAnsiStringToUnicodeString(&DelFileString, &InBuffer, TRUE);
				KdPrint(("DelFileString : %S", DelFileString.Buffer));
				int CurrentIndex = 0;
				for(int i = 0; i < LockedDocumentInformationLen; i++)
				{
					if(!RtlEqualUnicodeString(&DelFileString, &LockedDocumentFullPath[i], TRUE))
					{
						LockedDocumentFullPath[CurrentIndex++] = LockedDocumentFullPath[i];
					}
				}
				LockedDocumentInformationLen = (ULONG)CurrentIndex;
			}

			LockedDocumentInformationDeleting = FALSE;

			KdPrint(("New LockedDocumentInformationLen : %d", LockedDocumentInformationLen));
			break;
		}
	case NEW_DISABLE_FILE:
		{
			if(DisableFileName[DisableFileInformationLen].Length != 0 && DisableFileDeviceName[DisableFileInformationLen].Length != 0)
				KdPrint(("DisableFileInformationLen : %d", ++DisableFileInformationLen));
			else
				KdPrint(("DisableFileInformationLen : %d", DisableFileInformationLen));
			break;
		}
	case SET_LAST_DISABLE_FILE_NAME:
		{
			RtlAnsiStringToUnicodeString(&DisableFileName[DisableFileInformationLen], &InBuffer, TRUE);
			KdPrint(("ChangeLastDisableFileNameTo : %S", DisableFileName[DisableFileInformationLen].Buffer));
			break;
		}
	case SET_LAST_DISABLE_FILE_DEVICE_NAME:
		{
			RtlAnsiStringToUnicodeString(&DisableFileDeviceName[DisableFileInformationLen], &InBuffer, TRUE);
			KdPrint(("ChangeLastDisableFileDeviceNameTo : %S", DisableFileDeviceName[DisableFileInformationLen].Buffer));
			break;
		}
	case DEL_DISABLE_FILE_BY_FILE_NAME:
		{
			if(DisableFileInformationLen != 0)
			{
				DisableFileInformationDeleting = TRUE;
				
				UNICODE_STRING DelFileString;
				RtlAnsiStringToUnicodeString(&DelFileString, &InBuffer, TRUE);
				KdPrint(("DelFileString : %S", DelFileString.Buffer));
				int CurrentIndex = 0;
				for(int i = 0; i < DisableFileInformationLen; i++)
				{
					if(!RtlEqualUnicodeString(&DelFileString, &DisableFileName[i], TRUE))
					{
						DisableFileName[CurrentIndex] = DisableFileName[i];
						DisableFileDeviceName[CurrentIndex++] = DisableFileDeviceName[i];
					}
				}
				DisableFileInformationLen = (ULONG)CurrentIndex;
			}

			DisableFileInformationDeleting = FALSE;

			KdPrint(("New DisableFileInformationLen : %d", DisableFileInformationLen));
			break;
		}
	case DEL_DISABLE_FILE_BY_FILE_DEVICE_NAME:
		{
			if(DisableFileInformationLen != 0)
			{

				DisableFileInformationDeleting = TRUE;

				UNICODE_STRING DelFileDeviceString;
				RtlAnsiStringToUnicodeString(&DelFileDeviceString, &InBuffer, TRUE);
				int CurrentIndex = 0;
				for(int i = 0; i < DisableFileInformationLen; i++)
				{
					if(!RtlEqualUnicodeString(&DelFileDeviceString, &DisableFileDeviceName[i], TRUE))
					{
						DisableFileName[CurrentIndex] = DisableFileName[i];
						DisableFileDeviceName[CurrentIndex++] = DisableFileDeviceName[i];
					}
				}
				DisableFileInformationLen = (ULONG)CurrentIndex;
			}

			DisableFileInformationDeleting = FALSE;

			KdPrint(("New DisableFileInformationLen : %d", DisableFileInformationLen));
			break;
		}
	case NEW_DISABLE_DOCUMENT:
		{
			if(DisableDocumentPath[DisableDocumentInformationLen].Length != 0)
				KdPrint(("DisableDocumentInformationLen : %d", ++DisableDocumentInformationLen));
			else
				KdPrint(("DisableDocumentInformationLen : %d", DisableDocumentInformationLen));
			break;
		}
	case SET_LAST_DISABLE_DOCUMENT_DEVICE_NAME:
		{
			RtlAnsiStringToUnicodeString(&DisableDocumentDeviceName[DisableDocumentInformationLen], &InBuffer, TRUE);
			KdPrint(("ChangeLastDisableDocumentDeviceNameTo : %S", DisableDocumentDeviceName[DisableDocumentInformationLen].Buffer));
			break;
		}
	case SET_LAST_DISABLE_DOCUMENT_PATH:
		{
			RtlAnsiStringToUnicodeString(&DisableDocumentPath[DisableDocumentInformationLen], &InBuffer, TRUE);
			KdPrint(("ChangeLastDisableDocumentPathTo : %S", DisableDocumentPath[DisableDocumentInformationLen].Buffer));
			break;
		}
	case DEL_DISABLE_DOCUMENT_BY_PATH:
		{
			if(DisableDocumentInformationLen != 0)
			{

				DisableDocumentInformationDeleting = TRUE;
				
				UNICODE_STRING DelFileString;
				RtlAnsiStringToUnicodeString(&DelFileString, &InBuffer, TRUE);
				KdPrint(("DelFileString : %S", DelFileString.Buffer));
				int CurrentIndex = 0;
				for(int i = 0; i < DisableDocumentInformationLen; i++)
				{
					if(!RtlEqualUnicodeString(&DelFileString, &DisableDocumentPath[i], TRUE))
					{
						DisableDocumentPath[CurrentIndex++] = DisableDocumentPath[i];
					}
				}
				DisableDocumentInformationLen = (ULONG)CurrentIndex;
			}

			DisableDocumentInformationDeleting = FALSE;

			KdPrint(("New DisableDocumentInformationLen : %d", DisableDocumentInformationLen));
			break;
		}
	default:
		{
			KdPrint(("NO"));
			rtstatus = STATUS_INVALID_VARIANT;
			break;
		}
	}
	pIrp->IoStatus.Status = rtstatus;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	
	return pIrp->IoStatus.Status;
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
	KdPrint(("Call IRP_MJ_CLOSE"));
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return pIrp->IoStatus.Status;
}

NTSTATUS CreateDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	KdPrint(("Call IRP_MJ_CREATE"));
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return pIrp->IoStatus.Status;
}

NTSTATUS ReadDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	//rtStatus = STATUS_NOT_SUPPORTED;
	//rtStatus = STATUS_SUCCESS;
	pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return pIrp->IoStatus.Status;
}

NTSTATUS WriteDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	//rtStatus = STATUS_NOT_SUPPORTED;
	//rtStatus = STATUS_SUCCESS;
	pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return pIrp->IoStatus.Status;
}