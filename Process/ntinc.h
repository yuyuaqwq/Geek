#ifndef GEEK_PROCESS_NTINC_H_
#define GEEK_PROCESS_NTINC_H_

#define NT_SUCCESS(x) ((x) >= 0)
#define ProcessBasicInformation 0

typedef NTSTATUS(NTAPI* pfnNtWow64QueryInformationProcess64)(
    IN HANDLE ProcessHandle,
    IN ULONG ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );

typedef NTSTATUS(NTAPI* pfnNtWow64ReadVirtualMemory64)(
    IN HANDLE ProcessHandle,
    IN PVOID64 BaseAddress,
    OUT PVOID Buffer,
    IN ULONG64 Size,
    OUT PULONG64 NumberOfBytesRead
    );

typedef NTSTATUS(NTAPI* pfnNtWow64WriteVirtualMemory64)(
    IN HANDLE ProcessHandle,
    IN PVOID64 BaseAddress,
    OUT PVOID Buffer,
    IN ULONG64 Size,
    OUT PULONG64 NumberOfBytesRead
    );


typedef
NTSTATUS(WINAPI* pfnNtQueryInformationProcess)
(HANDLE ProcessHandle, ULONG ProcessInformationClass,
    PVOID ProcessInformation, UINT32 ProcessInformationLength,
    UINT32* ReturnLength);

typedef struct _PROCESS_BASIC_INFORMATION32 {
    NTSTATUS ExitStatus;
    UINT32 PebBaseAddress;
    UINT32 AffinityMask;
    UINT32 BasePriority;
    UINT32 UniqueProcessId;
    UINT32 InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION32;

typedef struct _UNICODE_STRING32
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING32, * PUNICODE_STRING32;

typedef struct _PEB32
{
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    ULONG Mutant;
    ULONG ImageBaseAddress;
    ULONG Ldr;
    ULONG ProcessParameters;
    ULONG SubSystemData;
    ULONG ProcessHeap;
    ULONG FastPebLock;
    ULONG AtlThunkSListPtr;
    ULONG IFEOKey;
    ULONG CrossProcessFlags;
    ULONG UserSharedInfoPtr;
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    ULONG ApiSetMap;
} PEB32, * PPEB32;

typedef struct _PEB_LDR_DATA32
{
    ULONG Length;
    BOOLEAN Initialized;
    ULONG SsHandle;
    LIST_ENTRY32 InLoadOrderModuleList;
    LIST_ENTRY32 InMemoryOrderModuleList;
    LIST_ENTRY32 InInitializationOrderModuleList;
    ULONG EntryInProgress;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
    LIST_ENTRY32 InLoadOrderLinks;
    LIST_ENTRY32 InMemoryOrderModuleList;
    LIST_ENTRY32 InInitializationOrderModuleList;
    ULONG DllBase;
    ULONG EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING32 FullDllName;
    UNICODE_STRING32 BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union
    {
        LIST_ENTRY32 HashLinks;
        ULONG SectionPointer;
    };
    ULONG CheckSum;
    union
    {
        ULONG TimeDateStamp;
        ULONG LoadedImports;
    };
    ULONG EntryPointActivationContext;
    ULONG PatchInformation;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

typedef struct _PROCESS_BASIC_INFORMATION64 {
    NTSTATUS ExitStatus;
    UINT32 Reserved0;
    UINT64 PebBaseAddress;
    UINT64 AffinityMask;
    UINT32 BasePriority;
    UINT32 Reserved1;
    UINT64 UniqueProcessId;
    UINT64 InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION64;
typedef struct _PEB64
{
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    ULONG64 Mutant;
    ULONG64 ImageBaseAddress;
    ULONG64 Ldr;
    ULONG64 ProcessParameters;
    ULONG64 SubSystemData;
    ULONG64 ProcessHeap;
    ULONG64 FastPebLock;
    ULONG64 AtlThunkSListPtr;
    ULONG64 IFEOKey;
    ULONG64 CrossProcessFlags;
    ULONG64 UserSharedInfoPtr;
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    ULONG64 ApiSetMap;
} PEB64, * PPEB64;

typedef struct _PEB_LDR_DATA64
{
    ULONG Length;
    BOOLEAN Initialized;
    ULONG64 SsHandle;
    LIST_ENTRY64 InLoadOrderModuleList;
    LIST_ENTRY64 InMemoryOrderModuleList;
    LIST_ENTRY64 InInitializationOrderModuleList;
    ULONG64 EntryInProgress;
} PEB_LDR_DATA64, * PPEB_LDR_DATA64;

typedef struct _UNICODE_STRING64
{
    USHORT Length;
    USHORT MaximumLength;
    ULONG64 Buffer;
} UNICODE_STRING64, * PUNICODE_STRING64;

typedef struct _LDR_DATA_TABLE_ENTRY64
{
    LIST_ENTRY64 InLoadOrderLinks;
    LIST_ENTRY64 InMemoryOrderModuleList;
    LIST_ENTRY64 InInitializationOrderModuleList;
    ULONG64 DllBase;
    ULONG64 EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING64 FullDllName;
    UNICODE_STRING64 BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union
    {
        LIST_ENTRY64 HashLinks;
        ULONG64 SectionPointer;
    };
    ULONG CheckSum;
    union
    {
        ULONG TimeDateStamp;
        ULONG64 LoadedImports;
    };
    ULONG64 EntryPointActivationContext;
    ULONG64 PatchInformation;
} LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;

#endif // GEEK_PROCESS_NTINC_H_