/**
 *
 * WOW64Ext Library
 *
 * Copyright (c) 2014 ReWolf
 * http://blog.rewolf.pl/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.    If not, see <http://www.gnu.org/licenses/>.
 *
 */
#pragma once

#include <windows.h>

#ifndef STATUS_SUCCESS
#     define STATUS_SUCCESS 0
#endif

#pragma pack(push)
#pragma pack(1)
template <class T>
struct _LIST_ENTRY_T
{
    T Flink;
    T Blink;
};

template <class T>
struct _UNICODE_STRING_T
{
    union
    {
        struct
        {
            WORD Length;
            WORD MaximumLength;
        };
        T dummy;
    };
    T Buffer;
};

template <class T>
struct _NT_TIB_T
{
    T ExceptionList;
    T StackBase;
    T StackLimit;
    T SubSystemTib;
    T FiberData;
    T ArbitraryUserPointer;
    T Self;
};

template <class T>
struct _CLIENT_ID
{
    T UniqueProcess;
    T UniqueThread;
};

template <class T>
struct _TEB_T_
{
    _NT_TIB_T<T> NtTib;
    T EnvironmentPointer;
    _CLIENT_ID<T> ClientId;
    T ActiveRpcHandle;
    T ThreadLocalStoragePointer;
    T ProcessEnvironmentBlock;
    DWORD LastErrorValue;
    DWORD CountOfOwnedCriticalSections;
    T CsrClientThread;
    T Win32ThreadInfo;
    DWORD User32Reserved[26];
    //rest of the structure is not defined for now, as it is not needed
};

template <class T>
struct _LDR_DATA_TABLE_ENTRY_T
{
    _LIST_ENTRY_T<T> InLoadOrderLinks;
    _LIST_ENTRY_T<T> InMemoryOrderLinks;
    _LIST_ENTRY_T<T> InInitializationOrderLinks;
    T DllBase;
    T EntryPoint;
    union
    {
        DWORD SizeOfImage;
        T dummy01;
    };
    _UNICODE_STRING_T<T> FullDllName;
    _UNICODE_STRING_T<T> BaseDllName;
    DWORD Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union
    {
        _LIST_ENTRY_T<T> HashLinks;
        struct 
        {
            T SectionPointer;
            T CheckSum;
        };
    };
    union
    {
        T LoadedImports;
        DWORD TimeDateStamp;
    };
    T EntryPointActivationContext;
    T PatchInformation;
    _LIST_ENTRY_T<T> ForwarderLinks;
    _LIST_ENTRY_T<T> ServiceTagLinks;
    _LIST_ENTRY_T<T> StaticLinks;
    T ContextInformation;
    T OriginalBase;
    _LARGE_INTEGER LoadTime;
};

template <class T>
struct _PEB_LDR_DATA_T
{
    DWORD Length;
    DWORD Initialized;
    T SsHandle;
    _LIST_ENTRY_T<T> InLoadOrderModuleList;
    _LIST_ENTRY_T<T> InMemoryOrderModuleList;
    _LIST_ENTRY_T<T> InInitializationOrderModuleList;
    T EntryInProgress;
    DWORD ShutdownInProgress;
    T ShutdownThreadId;

};

template <class T, class NGF, int A>
struct _PEB_T
{
    union
    {
        struct
        {
            BYTE InheritedAddressSpace;
            BYTE ReadImageFileExecOptions;
            BYTE BeingDebugged;
            BYTE BitField;
        };
        T dummy01;
    };
    T Mutant;
    T ImageBaseAddress;
    T Ldr;
    T ProcessParameters;
    T SubSystemData;
    T ProcessHeap;
    T FastPebLock;
    T AtlThunkSListPtr;
    T IFEOKey;
    T CrossProcessFlags;
    T UserSharedInfoPtr;
    DWORD SystemReserved;
    DWORD AtlThunkSListPtr32;
    T ApiSetMap;
    T TlsExpansionCounter;
    T TlsBitmap;
    DWORD TlsBitmapBits[2];
    T ReadOnlySharedMemoryBase;
    T HotpatchInformation;
    T ReadOnlyStaticServerData;
    T AnsiCodePageData;
    T OemCodePageData;
    T UnicodeCaseTableData;
    DWORD NumberOfProcessors;
    union
    {
        DWORD NtGlobalFlag;
        NGF dummy02;
    };
    LARGE_INTEGER CriticalSectionTimeout;
    T HeapSegmentReserve;
    T HeapSegmentCommit;
    T HeapDeCommitTotalFreeThreshold;
    T HeapDeCommitFreeBlockThreshold;
    DWORD NumberOfHeaps;
    DWORD MaximumNumberOfHeaps;
    T ProcessHeaps;
    T GdiSharedHandleTable;
    T ProcessStarterHelper;
    T GdiDCAttributeList;
    T LoaderLock;
    DWORD OSMajorVersion;
    DWORD OSMinorVersion;
    WORD OSBuildNumber;
    WORD OSCSDVersion;
    DWORD OSPlatformId;
    DWORD ImageSubsystem;
    DWORD ImageSubsystemMajorVersion;
    T ImageSubsystemMinorVersion;
    T ActiveProcessAffinityMask;
    T GdiHandleBuffer[A];
    T PostProcessInitRoutine; 
    T TlsExpansionBitmap; 
    DWORD TlsExpansionBitmapBits[32];
    T SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    T pShimData;
    T AppCompatInfo;
    _UNICODE_STRING_T<T> CSDVersion;
    T ActivationContextData;
    T ProcessAssemblyStorageMap;
    T SystemDefaultActivationContextData;
    T SystemAssemblyStorageMap;
    T MinimumStackCommit;
    T FlsCallback;
    _LIST_ENTRY_T<T> FlsListHead;
    T FlsBitmap;
    DWORD FlsBitmapBits[4];
    T FlsHighIndex;
    T WerRegistrationData;
    T WerShipAssertPtr;
    T pContextData;
    T pImageHeaderHash;
    T TracingFlags;
};


typedef struct _UNICODE_STRING32
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING32, * PUNICODE_STRING32;

typedef struct _UNICODE_STRING64
{
    USHORT Length;
    USHORT MaximumLength;
    ULONG64 Buffer;
} UNICODE_STRING64, * PUNICODE_STRING64;


typedef _LDR_DATA_TABLE_ENTRY_T<DWORD> LDR_DATA_TABLE_ENTRY32;
//typedef struct _LDR_DATA_TABLE_ENTRY32
//{
//    LIST_ENTRY32 InLoadOrderLinks;
//    LIST_ENTRY32 InMemoryOrderModuleList;
//    LIST_ENTRY32 InInitializationOrderModuleList;
//    ULONG DllBase;
//    ULONG EntryPoint;
//    ULONG SizeOfImage;
//    UNICODE_STRING32 FullDllName;
//    UNICODE_STRING32 BaseDllName;
//    ULONG Flags;
//    USHORT LoadCount;
//    USHORT TlsIndex;
//    union
//    {
//        LIST_ENTRY32 HashLinks;
//        ULONG SectionPointer;
//    };
//    ULONG CheckSum;
//    union
//    {
//        ULONG TimeDateStamp;
//        ULONG LoadedImports;
//    };
//    ULONG EntryPointActivationContext;
//    ULONG PatchInformation;
//} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

typedef _LDR_DATA_TABLE_ENTRY_T<DWORD64> LDR_DATA_TABLE_ENTRY64;
//typedef struct _LDR_DATA_TABLE_ENTRY64
//{
//    LIST_ENTRY64 InLoadOrderLinks;
//    LIST_ENTRY64 InMemoryOrderModuleList;
//    LIST_ENTRY64 InInitializationOrderModuleList;
//    ULONG64 DllBase;
//    ULONG64 EntryPoint;
//    ULONG SizeOfImage;
//    UNICODE_STRING64 FullDllName;
//    UNICODE_STRING64 BaseDllName;
//    ULONG Flags;
//    USHORT LoadCount;
//    USHORT TlsIndex;
//    union
//    {
//        LIST_ENTRY64 HashLinks;
//        ULONG64 SectionPointer;
//    };
//    ULONG CheckSum;
//    union
//    {
//        ULONG TimeDateStamp;
//        ULONG64 LoadedImports;
//    };
//    ULONG64 EntryPointActivationContext;
//    ULONG64 PatchInformation;
//} LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;


typedef _TEB_T_<DWORD> TEB32;
typedef _TEB_T_<DWORD64> TEB64;

typedef _PEB_LDR_DATA_T<DWORD> PEB_LDR_DATA32;
//typedef struct _PEB_LDR_DATA32
//{
//    DWORD Length;
//    DWORD Initialized;
//    DWORD SsHandle;
//    LIST_ENTRY32 InLoadOrderModuleList;
//    LIST_ENTRY32 InMemoryOrderModuleList;
//    LIST_ENTRY32 InInitializationOrderModuleList;
//    ULONG EntryInProgress;
//} PEB_LDR_DATA32, * PPEB_LDR_DATA32;

typedef _PEB_LDR_DATA_T<DWORD64> PEB_LDR_DATA64;
//typedef struct _PEB_LDR_DATA64
//{
//    DWORD Length;
//    DWORD Initialized;
//    DWORD64 SsHandle;
//    LIST_ENTRY64 InLoadOrderModuleList;
//    LIST_ENTRY64 InMemoryOrderModuleList;
//    LIST_ENTRY64 InInitializationOrderModuleList;
//    ULONG64 EntryInProgress;
//} PEB_LDR_DATA64, * PPEB_LDR_DATA64;

typedef _PEB_T<DWORD, DWORD64, 34> PEB32;
//typedef struct _PEB32
//{
//    UCHAR InheritedAddressSpace;
//    UCHAR ReadImageFileExecOptions;
//    UCHAR BeingDebugged;
//    UCHAR BitField;
//    ULONG Mutant;
//    ULONG ImageBaseAddress;
//    ULONG Ldr;
//    ULONG ProcessParameters;
//    ULONG SubSystemData;
//    ULONG ProcessHeap;
//    ULONG FastPebLock;
//    ULONG AtlThunkSListPtr;
//    ULONG IFEOKey;
//    ULONG CrossProcessFlags;
//    ULONG UserSharedInfoPtr;
//    ULONG SystemReserved;
//    ULONG AtlThunkSListPtr32;
//    ULONG ApiSetMap;
//} PEB32, * PPEB32;

typedef _PEB_T<DWORD64, DWORD, 30> PEB64;
//typedef struct _PEB64
//{
//    UCHAR InheritedAddressSpace;
//    UCHAR ReadImageFileExecOptions;
//    UCHAR BeingDebugged;
//    UCHAR BitField;
//    ULONG64 Mutant;
//    ULONG64 ImageBaseAddress;
//    ULONG64 Ldr;
//    ULONG64 ProcessParameters;
//    ULONG64 SubSystemData;
//    ULONG64 ProcessHeap;
//    ULONG64 FastPebLock;
//    ULONG64 AtlThunkSListPtr;
//    ULONG64 IFEOKey;
//    ULONG64 CrossProcessFlags;
//    ULONG64 UserSharedInfoPtr;
//    ULONG SystemReserved;
//    ULONG AtlThunkSListPtr32;
//    ULONG64 ApiSetMap;
//} PEB64, * PPEB64;


struct _XSAVE_FORMAT64
{
    WORD ControlWord;
    WORD StatusWord;
    BYTE TagWord;
    BYTE Reserved1;
    WORD ErrorOpcode;
    DWORD ErrorOffset;
    WORD ErrorSelector;
    WORD Reserved2;
    DWORD DataOffset;
    WORD DataSelector;
    WORD Reserved3;
    DWORD MxCsr;
    DWORD MxCsr_Mask;
    _M128A FloatRegisters[8];
    _M128A XmmRegisters[16];
    BYTE Reserved4[96];
};

struct _CONTEXT64
{
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;
    DWORD ContextFlags;
    DWORD MxCsr;
    WORD SegCs;
    WORD SegDs;
    WORD SegEs;
    WORD SegFs;
    WORD SegGs;
    WORD SegSs;
    DWORD EFlags;
    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;
    DWORD64 Rip;
    _XSAVE_FORMAT64 FltSave;
    _M128A Header[2];
    _M128A Legacy[8];
    _M128A Xmm0;
    _M128A Xmm1;
    _M128A Xmm2;
    _M128A Xmm3;
    _M128A Xmm4;
    _M128A Xmm5;
    _M128A Xmm6;
    _M128A Xmm7;
    _M128A Xmm8;
    _M128A Xmm9;
    _M128A Xmm10;
    _M128A Xmm11;
    _M128A Xmm12;
    _M128A Xmm13;
    _M128A Xmm14;
    _M128A Xmm15;
    _M128A VectorRegister[26];
    DWORD64 VectorControl;
    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
};

typedef WOW64_CONTEXT _CONTEXT32;





typedef struct _RTL_USER_PROCESS_PARAMETERS32 {
    BYTE                     Reserved1[16];
    DWORD                    Reserved2[10];
    UNICODE_STRING32 ImagePathName;
    UNICODE_STRING32 CommandLine;
} RTL_USER_PROCESS_PARAMETERS32, * PRTL_USER_PROCESS_PARAMETERS32;

typedef struct _RTL_USER_PROCESS_PARAMETERS64 {
    BYTE                     Reserved1[16];
    LONG64                    Reserved2[10];
    UNICODE_STRING64 ImagePathName;
    UNICODE_STRING64 CommandLine;
} RTL_USER_PROCESS_PARAMETERS64, * PRTL_USER_PROCESS_PARAMETERS64;


// Below defines for .ContextFlags field are taken from WinNT.h
#ifndef CONTEXT_AMD64
#define CONTEXT_AMD64 0x100000
#endif

#define CONTEXT64_CONTROL (CONTEXT_AMD64 | 0x1L)
#define CONTEXT64_INTEGER (CONTEXT_AMD64 | 0x2L)
#define CONTEXT64_SEGMENTS (CONTEXT_AMD64 | 0x4L)
#define CONTEXT64_FLOATING_POINT    (CONTEXT_AMD64 | 0x8L)
#define CONTEXT64_DEBUG_REGISTERS (CONTEXT_AMD64 | 0x10L)
#define CONTEXT64_FULL (CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_FLOATING_POINT)
#define CONTEXT64_ALL (CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_SEGMENTS | CONTEXT64_FLOATING_POINT | CONTEXT64_DEBUG_REGISTERS)
#define CONTEXT64_XSTATE (CONTEXT_AMD64 | 0x20L)

#pragma pack(pop)
