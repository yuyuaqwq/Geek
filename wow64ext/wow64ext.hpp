#ifndef GEEK_Wow64EXT_Wow64EXT_H_
#define GEEK_Wow64EXT_Wow64EXT_H_

#include <memory>

#include <Windows.h>

#include <Geek/Wow64ext/internal.h>
#include <Geek/Wow64ext/Wow64ext.h>

/*
* https://github.com/rwfpl/rewolf-Wow64ext
*/

namespace Geek {

class Wow64 {
public:
    static bool Wow64Operation(HANDLE hProcess) {
        BOOL source, target;
        IsWow64Process(GetCurrentProcess(), &source);
        IsWow64Process(hProcess, &target);

        SYSTEM_INFO si;
        GetSystemInfo(&si);
        if (target == FALSE && source == TRUE) {
            return true;
        }
        else if (target == TRUE && source == TRUE || si.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64 ||
            si.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_IA64) {
            return false;
        }
        return false;
    }

public:

    Wow64() {
        Wow64ExtInit();
    }

    static void* Wow64Malloc(size_t size) {
        return HeapAlloc(ms_heap, 0, size);
    }

    static void Wow64Free(void* ptr) {
        if (nullptr != ptr)
            HeapFree(ms_heap, 0, ptr);
    }

    static VOID __cdecl Wow64ExtInit() {
        if (ms_heap == NULL) {
            ::IsWow64Process(GetCurrentProcess(), &ms_is_wow64);
            ms_heap = GetProcessHeap();
        }
    }

    static DWORD64 __cdecl X64Call(DWORD64 func, int argC, ...) {
#ifdef _WIN64
        return 0;
#else
        if (!ms_is_wow64)
            return 0;

        va_list args;
        va_start(args, argC);
        reg64 _rcx = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
        reg64 _rdx = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
        reg64 _r8 = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
        reg64 _r9 = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
        reg64 _rax = { 0 };

        reg64 restArgs = { (DWORD64)&va_arg(args, DWORD64) };

        // conversion to QWORD for easier use in inline assembly
        reg64 _argC = { (DWORD64)argC };
        DWORD back_esp = 0;
        WORD back_fs = 0;

        __asm
        {
            ;// reset FS segment, to properly handle RFG
            mov    back_fs, fs
                mov    eax, 0x2B
                mov    fs, ax

                ;// keep original esp in back_esp variable
            mov    back_esp, esp

                ;// align esp to 0x10, without aligned stack some syscalls may return errors !
            ;// (actually, for syscalls it is sufficient to align to 8, but SSE opcodes 
            ;// requires 0x10 alignment), it will be further adjusted according to the
            ;// number of arguments above 4
            and esp, 0xFFFFFFF0

                X64_Start();

            ;// below code is compiled as x86 inline asm, but it is executed as x64 code
            ;// that's why it need sometimes REX_W() macro, right column contains detailed
            ;// transcription how it will be interpreted by CPU

            ;// fill first four arguments
            REX_W mov    ecx, _rcx.dw[0];// mov     rcx, qword ptr [_rcx]
            REX_W mov    edx, _rdx.dw[0];// mov     rdx, qword ptr [_rdx]
            push   _r8.v;// push    qword ptr [_r8]
            X64_Pop(_R8); ;// pop     r8
            push   _r9.v;// push    qword ptr [_r9]
            X64_Pop(_R9); ;// pop     r9
            ;//
            REX_W mov    eax, _argC.dw[0];// mov     rax, qword ptr [_argC]
            ;// 
            ;// final stack adjustment, according to the    ;//
            ;// number of arguments above 4                 ;// 
            test   al, 1;// test    al, 1
            jnz    _no_adjust;// jnz     _no_adjust
            sub    esp, 8;// sub     rsp, 8
        _no_adjust:;//
            ;// 
            push   edi;// push    rdi
            REX_W mov    edi, restArgs.dw[0];// mov     rdi, qword ptr [restArgs]
            ;// 
            ;// put rest of arguments on the stack          ;// 
            REX_W test   eax, eax;// test    rax, rax
            jz     _ls_e;// je      _ls_e
            REX_W lea    edi, dword ptr[edi + 8 * eax - 8];// lea     rdi, [rdi + rax*8 - 8]
            ;// 
        _ls:;// 
            REX_W test   eax, eax;// test    rax, rax
            jz     _ls_e;// je      _ls_e
            push   dword ptr[edi];// push    qword ptr [rdi]
            REX_W sub    edi, 8;// sub     rdi, 8
            REX_W sub    eax, 1;// sub     rax, 1
            jmp    _ls;// jmp     _ls
        _ls_e:;// 
            ;// 
            ;// create stack space for spilling registers   ;// 
            REX_W sub    esp, 0x20;// sub     rsp, 20h
            ;// 
            call   func;// call    qword ptr [func]
            ;// 
            ;// cleanup stack                               ;// 
            REX_W mov    ecx, _argC.dw[0];// mov     rcx, qword ptr [_argC]
            REX_W lea    esp, dword ptr[esp + 8 * ecx + 0x20];// lea     rsp, [rsp + rcx*8 + 20h]
            ;// 
            pop    edi;// pop     rdi
            ;// 
// set return value                             ;// 
            REX_W mov    _rax.dw[0], eax;// mov     qword ptr [_rax], rax

            X64_End();

            mov    ax, ds
                mov    ss, ax
                mov    esp, back_esp

                ;// restore FS segment
            mov    ax, back_fs
                mov    fs, ax
        }
        return _rax.v;
#endif // !_WIN64
    }

    static DWORD64 __cdecl GetModuleHandle64(const wchar_t* lpModuleName) {
        if (!ms_is_wow64)
            return 0;

        TEB64 teb64;
        GetMem64(&teb64, GetTEB64(), sizeof(TEB64));

        PEB64 peb64;
        GetMem64(&peb64, teb64.ProcessEnvironmentBlock, sizeof(PEB64));
        PEB_LDR_DATA64 ldr;
        GetMem64(&ldr, peb64.Ldr, sizeof(PEB_LDR_DATA64));

        DWORD64 LastEntry = peb64.Ldr + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList);
        LDR_DATA_TABLE_ENTRY64 head;
        head.InLoadOrderLinks.Flink = ldr.InLoadOrderModuleList.Flink;
        do
        {
            GetMem64(&head, head.InLoadOrderLinks.Flink, sizeof(LDR_DATA_TABLE_ENTRY64));

            std::unique_ptr<wchar_t, void(*)(void*)> tempBuf{ (wchar_t*)Wow64Malloc(head.BaseDllName.MaximumLength), Wow64Free };
            if (nullptr == tempBuf)
                return 0;

            GetMem64(tempBuf.get(), head.BaseDllName.Buffer, head.BaseDllName.MaximumLength);

            if (0 == _wcsicmp(lpModuleName, tempBuf.get())) {
                return head.DllBase;
            }
        } while (head.InLoadOrderLinks.Flink != LastEntry);

        return 0;
    }

    static VOID __cdecl SetLastErrorFromX64Call(DWORD64 status) {
        typedef ULONG(WINAPI* RtlNtStatusToDosError_t)(NTSTATUS Status);
        typedef ULONG(WINAPI* RtlSetLastWin32Error_t)(NTSTATUS Status);

        static RtlNtStatusToDosError_t RtlNtStatusToDosError = nullptr;
        static RtlSetLastWin32Error_t RtlSetLastWin32Error = nullptr;

        if ((nullptr == RtlNtStatusToDosError) || (nullptr == RtlSetLastWin32Error))
        {
            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
            RtlNtStatusToDosError = (RtlNtStatusToDosError_t)GetProcAddress(ntdll, "RtlNtStatusToDosError");
            RtlSetLastWin32Error = (RtlSetLastWin32Error_t)GetProcAddress(ntdll, "RtlSetLastWin32Error");
        }

        if ((nullptr != RtlNtStatusToDosError) && (nullptr != RtlSetLastWin32Error))
        {
            RtlSetLastWin32Error(RtlNtStatusToDosError((DWORD)status));
        }
    }

    static DWORD64 __cdecl GetProcAddress64(DWORD64 hModule, const char* funcName) {
        static DWORD64 _LdrGetProcedureAddress = 0;
        if (0 == _LdrGetProcedureAddress)
        {
            _LdrGetProcedureAddress = GetLdrGetProcedureAddress();
            if (0 == _LdrGetProcedureAddress)
                return 0;
        }

        _UNICODE_STRING_T<DWORD64> fName = { 0 };
        fName.Buffer = (DWORD64)funcName;
        fName.Length = (WORD)strlen(funcName);
        fName.MaximumLength = fName.Length + 1;
        DWORD64 funcRet = 0;
        X64Call(_LdrGetProcedureAddress, 4, (DWORD64)hModule, (DWORD64)&fName, (DWORD64)0, (DWORD64)&funcRet);
        return funcRet;
    }

    static SIZE_T __cdecl VirtualQueryEx64(HANDLE hProcess, DWORD64 lpAddress, MEMORY_BASIC_INFORMATION64* lpBuffer, SIZE_T dwLength) {
        static DWORD64 ntqvm = 0;
        if (0 == ntqvm)
        {
            ntqvm = GetProcAddress64(GetNTDLL64(), "NtQueryVirtualMemory");
            if (0 == ntqvm)
                return 0;
        }
        DWORD64 ret = 0;
        DWORD64 status = X64Call(ntqvm, 6, (DWORD64)hProcess, lpAddress, (DWORD64)0, (DWORD64)lpBuffer, (DWORD64)dwLength, (DWORD64)&ret);
        if (STATUS_SUCCESS != status)
            SetLastErrorFromX64Call(status);
        return (SIZE_T)ret;
    }

    static DWORD64 __cdecl VirtualAllocEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
        static DWORD64 ntavm = 0;
        if (0 == ntavm)
        {
            ntavm = GetProcAddress64(GetNTDLL64(), "NtAllocateVirtualMemory");
            if (0 == ntavm)
                return 0;
        }

        DWORD64 tmpAddr = lpAddress;
        DWORD64 tmpSize = dwSize;
        DWORD64 ret = X64Call(ntavm, 6, (DWORD64)hProcess, (DWORD64)&tmpAddr, (DWORD64)0, (DWORD64)&tmpSize, (DWORD64)flAllocationType, (DWORD64)flProtect);
        if (STATUS_SUCCESS != ret)
        {
            SetLastErrorFromX64Call(ret);
            return FALSE;
        }
        else
            return tmpAddr;
    }

    static BOOL __cdecl VirtualFreeEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
        static DWORD64 ntfvm = 0;
        if (0 == ntfvm)
        {
            ntfvm = GetProcAddress64(GetNTDLL64(), "NtFreeVirtualMemory");
            if (0 == ntfvm)
                return 0;
        }

        DWORD64 tmpAddr = lpAddress;
        DWORD64 tmpSize = dwSize;
        DWORD64 ret = X64Call(ntfvm, 4, (DWORD64)hProcess, (DWORD64)&tmpAddr, (DWORD64)&tmpSize, (DWORD64)dwFreeType);
        if (STATUS_SUCCESS != ret)
        {
            SetLastErrorFromX64Call(ret);
            return FALSE;
        }
        else
            return TRUE;
    }

    static BOOL __cdecl VirtualProtectEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* lpflOldProtect) {
        static DWORD64 ntpvm = 0;
        if (0 == ntpvm)
        {
            ntpvm = GetProcAddress64(GetNTDLL64(), "NtProtectVirtualMemory");
            if (0 == ntpvm)
                return 0;
        }

        DWORD64 tmpAddr = lpAddress;
        DWORD64 tmpSize = dwSize;
        DWORD64 ret = X64Call(ntpvm, 5, (DWORD64)hProcess, (DWORD64)&tmpAddr, (DWORD64)&tmpSize, (DWORD64)flNewProtect, (DWORD64)lpflOldProtect);
        if (STATUS_SUCCESS != ret)
        {
            SetLastErrorFromX64Call(ret);
            return FALSE;
        }
        else
            return TRUE;
    }

    static BOOL __cdecl ReadProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) {
        static DWORD64 nrvm = 0;
        if (0 == nrvm)
        {
            nrvm = GetProcAddress64(GetNTDLL64(), "NtReadVirtualMemory");
            if (0 == nrvm)
                return 0;
        }
        DWORD64 numOfBytes = lpNumberOfBytesRead ? *lpNumberOfBytesRead : 0;
        DWORD64 ret = X64Call(nrvm, 5, (DWORD64)hProcess, lpBaseAddress, (DWORD64)lpBuffer, (DWORD64)nSize, (DWORD64)&numOfBytes);
        if (STATUS_SUCCESS != ret)
        {
            SetLastErrorFromX64Call(ret);
            return FALSE;
        }
        else
        {
            if (lpNumberOfBytesRead)
                *lpNumberOfBytesRead = (SIZE_T)numOfBytes;
            return TRUE;
        }
    }

    static BOOL __cdecl WriteProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
        static DWORD64 nrvm = 0;
        if (0 == nrvm)
        {
            nrvm = GetProcAddress64(GetNTDLL64(), "NtWriteVirtualMemory");
            if (0 == nrvm)
                return 0;
        }
        DWORD64 numOfBytes = lpNumberOfBytesWritten ? *lpNumberOfBytesWritten : 0;
        DWORD64 ret = X64Call(nrvm, 5, (DWORD64)hProcess, lpBaseAddress, (DWORD64)lpBuffer, (DWORD64)nSize, (DWORD64)&numOfBytes);
        if (STATUS_SUCCESS != ret)
        {
            SetLastErrorFromX64Call(ret);
            return FALSE;
        }
        else
        {
            if (lpNumberOfBytesWritten)
                *lpNumberOfBytesWritten = (SIZE_T)numOfBytes;
            return TRUE;
        }
    }

    static BOOL __cdecl GetThreadContext64(HANDLE hThread, _CONTEXT64* lpContext) {
        static DWORD64 gtc = 0;
        if (0 == gtc)
        {
            gtc = GetProcAddress64(GetNTDLL64(), "NtGetContextThread");
            if (0 == gtc)
                return 0;
        }
        DWORD64 ret = X64Call(gtc, 2, (DWORD64)hThread, (DWORD64)lpContext);
        if (STATUS_SUCCESS != ret)
        {
            SetLastErrorFromX64Call(ret);
            return FALSE;
        }
        else
            return TRUE;
    }

    static BOOL __cdecl SetThreadContext64(HANDLE hThread, _CONTEXT64* lpContext) {
        static DWORD64 stc = 0;
        if (0 == stc)
        {
            stc = GetProcAddress64(GetNTDLL64(), "NtSetContextThread");
            if (0 == stc)
                return 0;
        }
        DWORD64 ret = X64Call(stc, 2, (DWORD64)hThread, (DWORD64)lpContext);
        if (STATUS_SUCCESS != ret)
        {
            SetLastErrorFromX64Call(ret);
            return FALSE;
        }
        else
            return TRUE;
    }

    static void GetMem64(void* dstMem, DWORD64 srcMem, size_t sz) {
#ifdef _WIN64
        return;
#else
        if ((nullptr == dstMem) || (0 == srcMem) || (0 == sz))
            return;

        reg64 _src = { srcMem };

        __asm
        {
            X64_Start();

            ;// below code is compiled as x86 inline asm, but it is executed as x64 code
            ;// that's why it need sometimes REX_W() macro, right column contains detailed
            ;// transcription how it will be interpreted by CPU

            push   edi;// push     rdi
            push   esi;// push     rsi
            ;//
            mov    edi, dstMem;// mov      edi, dword ptr [dstMem]        ; high part of RDI is zeroed
            REX_W mov    esi, _src.dw[0];// mov      rsi, qword ptr [_src]
            mov    ecx, sz;// mov      ecx, dword ptr [sz]            ; high part of RCX is zeroed
            ;//
            mov    eax, ecx;// mov      eax, ecx
            and eax, 3;// and      eax, 3
            shr    ecx, 2;// shr      ecx, 2
            ;//
            rep    movsd;// rep movs dword ptr [rdi], dword ptr [rsi]
            ;//
            test   eax, eax;// test     eax, eax
            je     _move_0;// je       _move_0
            cmp    eax, 1;// cmp      eax, 1
            je     _move_1;// je       _move_1
            ;//
            movsw;// movs     word ptr [rdi], word ptr [rsi]
            cmp    eax, 2;// cmp      eax, 2
            je     _move_0;// je       _move_0
            ;//
        _move_1:;//
            movsb;// movs     byte ptr [rdi], byte ptr [rsi]
            ;//
        _move_0:;//
            pop    esi;// pop      rsi
            pop    edi;// pop      rdi

            X64_End();
        }
#endif // _WIN64
    }

    static bool CmpMem64(const void* dstMem, DWORD64 srcMem, size_t sz) {
#ifdef _WIN64
        return false;
#else
        if ((nullptr == dstMem) || (0 == srcMem) || (0 == sz))
            return false;

        bool result = false;
        reg64 _src = { srcMem };
        __asm
        {
            X64_Start();

            ;// below code is compiled as x86 inline asm, but it is executed as x64 code
            ;// that's why it need sometimes REX_W() macro, right column contains detailed
            ;// transcription how it will be interpreted by CPU

            push   edi;// push      rdi
            push   esi;// push      rsi
            ;//           
            mov    edi, dstMem;// mov       edi, dword ptr [dstMem]       ; high part of RDI is zeroed
            REX_W mov    esi, _src.dw[0];// mov       rsi, qword ptr [_src]
            mov    ecx, sz;// mov       ecx, dword ptr [sz]           ; high part of RCX is zeroed
            ;//           
            mov    eax, ecx;// mov       eax, ecx
            and eax, 3;// and       eax, 3
            shr    ecx, 2;// shr       ecx, 2
            ;// 
            repe   cmpsd;// repe cmps dword ptr [rsi], dword ptr [rdi]
            jnz     _ret_false;// jnz       _ret_false
            ;// 
            test   eax, eax;// test      eax, eax
            je     _move_0;// je        _move_0
            cmp    eax, 1;// cmp       eax, 1
            je     _move_1;// je        _move_1
            ;// 
            cmpsw;// cmps      word ptr [rsi], word ptr [rdi]
            jnz     _ret_false;// jnz       _ret_false
            cmp    eax, 2;// cmp       eax, 2
            je     _move_0;// je        _move_0
            ;// 
        _move_1:;// 
            cmpsb;// cmps      byte ptr [rsi], byte ptr [rdi]
            jnz     _ret_false;// jnz       _ret_false
            ;// 
        _move_0:;// 
            mov    result, 1;// mov       byte ptr [result], 1
            ;// 
        _ret_false:;// 
            pop    esi;// pop      rsi
            pop    edi;// pop      rdi

            X64_End();
        }

        return result;
#endif
    }

    static DWORD64 GetTEB64() {
#ifdef _WIN64
        return 0;
#else
        reg64 reg;
        reg.v = 0;

        X64_Start();
        // R12 register should always contain pointer to TEB64 in Wow64 processes
        X64_Push(_R12);
        // below pop will pop QWORD from stack, as we're in x64 mode now
        __asm pop reg.dw[0]
            X64_End();

        return reg.v;
#endif // _WIN64
    }

    static DWORD64 GetNTDLL64() {
        static DWORD64 ntdll64 = 0;
        if (0 != ntdll64)
            return ntdll64;

        ntdll64 = GetModuleHandle64(L"ntdll.dll");
        return ntdll64;
    }

    static DWORD64 GetLdrGetProcedureAddress() {
        DWORD64 modBase = GetNTDLL64();
        if (0 == modBase)
            return 0;

        IMAGE_DOS_HEADER idh;
        GetMem64(&idh, modBase, sizeof(idh));

        IMAGE_NT_HEADERS64 inh;
        GetMem64(&inh, modBase + idh.e_lfanew, sizeof(IMAGE_NT_HEADERS64));

        IMAGE_DATA_DIRECTORY& idd = inh.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

        if (0 == idd.VirtualAddress)
            return 0;

        IMAGE_EXPORT_DIRECTORY ied;
        GetMem64(&ied, modBase + idd.VirtualAddress, sizeof(ied));

        std::unique_ptr<DWORD, void(*)(void*)> rvaTable{ (DWORD*)Wow64Malloc(sizeof(DWORD) * ied.NumberOfFunctions), Wow64Free };
        if (nullptr == rvaTable)
            return 0;
            
        GetMem64(rvaTable.get(), modBase + ied.AddressOfFunctions, sizeof(DWORD) * ied.NumberOfFunctions);

        std::unique_ptr<WORD, void(*)(void*)> ordTable{ (WORD*)Wow64Malloc(sizeof(WORD) * ied.NumberOfFunctions), Wow64Free };
        if (nullptr == ordTable)
            return 0;
            
        GetMem64(ordTable.get(), modBase + ied.AddressOfNameOrdinals, sizeof(WORD) * ied.NumberOfFunctions);

        std::unique_ptr<DWORD, void(*)(void*)> nameTable { (DWORD*)Wow64Malloc(sizeof(DWORD) * ied.NumberOfNames), Wow64Free };
        if (nullptr == nameTable)
            return 0;

        GetMem64(nameTable.get(), modBase + ied.AddressOfNames, sizeof(DWORD) * ied.NumberOfNames);

        // lazy search, there is no need to use binsearch for just one function
        for (DWORD i = 0; i < ied.NumberOfFunctions; i++)
        {
            if (!CmpMem64("LdrGetProcedureAddress", modBase + nameTable.get()[i], sizeof("LdrGetProcedureAddress")))
                continue;
            else
                return modBase + rvaTable.get()[ordTable.get()[i]];
        }
        return 0;
    }

private:
    inline static HANDLE ms_heap = NULL;
    inline static BOOL ms_is_wow64 = FALSE;
};

}

#endif // GEEK_Wow64EXT_Wow64EXT_H_