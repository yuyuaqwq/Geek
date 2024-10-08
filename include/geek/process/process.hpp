#ifndef GEEK_PROCESS_PROCESS_HPP_
#define GEEK_PROCESS_PROCESS_HPP_

#include <string>
#include <array>
#include <vector>
#include <map>
#include <optional>
#include <functional>
#include <mutex>
#include <cstddef>

#ifndef WINNT
#include <Windows.h>
#include <tlhelp32.h>
//#include <Winternl.h>
#else
#include <ntifs.h>
#endif

#undef min
#undef max

#include <Geek/process/ntinc.h>
#include <Geek/process/module_info.hpp>
#include <Geek/process/memory_info.hpp>
#include <Geek/process/process_info.hpp>
#include <Geek/handle.hpp>
#include <Geek/pe/image.hpp>
#include <Geek/thread/thread.hpp>
#include <Geek/wow64ext/wow64ext.hpp>
#include <Geek/string/string.hpp>
#include <Geek/file/file.hpp>

namespace Geek {

static inline Wow64 ms_wow64;
static inline const HANDLE kCurrentProcess = (HANDLE)-1;
class Process {
public:
    static std::optional<Process> Open(DWORD pid, DWORD desiredAccess = PROCESS_ALL_ACCESS) {
        auto hProcess = OpenProcess(desiredAccess, FALSE, pid);
        if (hProcess == NULL) {
            return {};
        }
        return Process{ UniqueHandle(hProcess) };
    }

    static std::optional<Process> Open(std::wstring_view process_name, DWORD desiredAccess = PROCESS_ALL_ACCESS, size_t count = 1) {
        auto pid = GetProcessIdByProcessName(process_name, count);
        if (!pid) {
            return {};
        }
        return Open(pid.value(), desiredAccess);
    }

    /*
    * CREATE_SUSPENDED:挂起目标进程
    */
    static std::optional<std::tuple<Process, Thread>> Create(std::wstring_view command, BOOL inheritHandles = FALSE, DWORD creationFlags = 0) {
        std::wstring command_ = command.data();
        STARTUPINFOW startupInfo{ sizeof(startupInfo) };
        PROCESS_INFORMATION processInformation{ 0 };
        if (!CreateProcessW(NULL, (LPWSTR)command_.c_str(), NULL, NULL, inheritHandles, creationFlags, NULL, NULL, &startupInfo, &processInformation)) {
            return {};
        }
        return std::tuple{ Process{ UniqueHandle{ processInformation.hProcess } },  Thread{ UniqueHandle{ processInformation.hThread } } };
    }

    /*
    * L"explorer.exe"
    */
    static std::optional<std::tuple<Process, Thread>> CreateByToken(std::wstring_view tokenProcessName, std::wstring_view command, BOOL inheritHandles = FALSE, DWORD creationFlags = 0, STARTUPINFOW* si = NULL, PROCESS_INFORMATION* pi = NULL) {
        HANDLE hToken_ = NULL;
        auto pid = GetProcessIdByProcessName(tokenProcessName);
        if (!pid) {
            return {};
        }
        UniqueHandle hProcess{ OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid.value()) };
        OpenProcessToken(hProcess.Get(), TOKEN_ALL_ACCESS, &hToken_);
        if (hToken_ == NULL) {
            return {};
        }
        UniqueHandle hToken{ hToken_ };

        if (!si) {
            STARTUPINFOW tempSi{ 0 };
            si = &tempSi;
        }
        if (!pi) {
            PROCESS_INFORMATION tempPi{ 0 };
            pi = &tempPi;
        }
        si->cb = sizeof(STARTUPINFO);
        // si->lpDesktop = L"winsta0\\default";
        si->dwFlags |= STARTF_USESHOWWINDOW;
        si->wShowWindow |= SW_HIDE;
        std::wstring command_copy = command.data();
        BOOL ret = CreateProcessAsUserW(hToken.Get(), NULL, (LPWSTR)command_copy.c_str(), NULL, NULL, inheritHandles, creationFlags | NORMAL_PRIORITY_CLASS, NULL, NULL, si, pi);
        if (!ret) {
            return {};
        }
        return std::tuple { Process{ UniqueHandle(pi->hProcess) }, Thread{ UniqueHandle(pi->hThread) } };
    }
    

    explicit Process(UniqueHandle process_handle) noexcept :
        process_handle_ { std::move(process_handle) } {
    }



    bool Terminate(uint32_t exitCode) {
        bool ret = ::TerminateProcess(Get(), exitCode);
        process_handle_.Reset();
        return ret;
    }

    bool SetDebugPrivilege(bool IsEnable) {
        DWORD LastError = 0;
        HANDLE TokenHandle = 0;

        if (!OpenProcessToken(Get(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle)) {
            LastError = GetLastError();
            if (TokenHandle) {
                CloseHandle(TokenHandle);
            }
            return LastError;
        }
        TOKEN_PRIVILEGES TokenPrivileges;
        memset(&TokenPrivileges, 0, sizeof(TOKEN_PRIVILEGES));
        LUID v1;
        if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &v1)) {
            LastError = GetLastError();
            CloseHandle(TokenHandle);
            return LastError;
        }
        TokenPrivileges.PrivilegeCount = 1;
        TokenPrivileges.Privileges[0].Luid = v1;
        if (IsEnable) {
            TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        }
        else {
            TokenPrivileges.Privileges[0].Attributes = 0;
        }
        AdjustTokenPrivileges(TokenHandle, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        LastError = GetLastError();
        CloseHandle(TokenHandle);
        return LastError;
    }


    HANDLE Get() const noexcept {
        if (this == nullptr) {
            return kCurrentProcess;
        }
        return process_handle_.Get();
    }

    DWORD GetId() const noexcept {
        return GetProcessId(Get());
    }

    bool IsX86() const noexcept {
        auto handle = Get();

        ::BOOL IsWow64;
        if (!::IsWow64Process(handle, &IsWow64)) {
            return false;
        }

        if (IsWow64) {
            return true;
        }

        ::SYSTEM_INFO SystemInfo = { 0 };
        ::GetNativeSystemInfo(&SystemInfo);
        if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
            return false;
        }
        else if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
            return true;
        }
        return false;

    }

    bool IsCur() const {
        return this == nullptr || process_handle_.Get() == kCurrentProcess;
    }
        
    /*
    * Memory
    */
    std::optional<uint64_t> AllocMemory(uint64_t addr, size_t len, DWORD type = MEM_RESERVE | MEM_COMMIT, DWORD protect = PAGE_READWRITE) {
        if (ms_wow64.Wow64Operation(Get())) {
            auto ptr = ms_wow64.VirtualAllocEx64(Get(), (DWORD64)addr, len, type, protect);
            if (ptr == 0) {
                return {};
            }
            return static_cast<uint64_t>(ptr);
        }
        auto ptr = VirtualAllocEx(Get(), (LPVOID)addr, len, type, protect);
        if (ptr == NULL) {
            return {};
        }
        return reinterpret_cast<uint64_t>(ptr);
    }

    std::optional<uint64_t> AllocMemory(size_t len, DWORD type = MEM_RESERVE | MEM_COMMIT, DWORD protect = PAGE_READWRITE) {
        return AllocMemory(NULL, len, type, protect);
    }

    bool FreeMemory(uint64_t addr, size_t size = 0, DWORD type = MEM_RELEASE) {
        if (ms_wow64.Wow64Operation(Get())) {
            return ms_wow64.VirtualFreeEx64(Get(), (DWORD64)addr, size, type);
        }
        return VirtualFreeEx(Get(), (LPVOID)addr, size, type);
    }

    bool ReadMemory(uint64_t addr, void* buf, size_t len) const {
        SIZE_T readByte;
        if (IsCur()) {
            memcpy(buf, (void*)addr, len);
            return true;
        }
        if (ms_wow64.Wow64Operation(Get())) {
            HMODULE NtdllModule = ::GetModuleHandleW(L"ntdll.dll");
            pfnNtWow64ReadVirtualMemory64 NtWow64ReadVirtualMemory64 = (pfnNtWow64ReadVirtualMemory64)::GetProcAddress(NtdllModule, "NtWow64ReadVirtualMemory64");
            if (!NT_SUCCESS(NtWow64ReadVirtualMemory64(Get(), addr, buf, len, NULL))) {
                return false;
            }
        }
        else {
            if (!::ReadProcessMemory(Get(), (void*)addr, buf, len, &readByte)) {
                // throw ProcessException(ProcessException::Type::kReadProcessMemoryError);
                return false;
            }
        }
        return true;
    }

    std::optional<std::vector<uint8_t>> ReadMemory(uint64_t addr, size_t len) const {
        std::vector<uint8_t> buf;
        buf.resize(len, 0);
        if (!ReadMemory(addr, buf.data(), len)) {
            return {};
        }
        return buf;
    }

    bool WriteMemory(uint64_t addr, const void* buf, size_t len, bool force = false) {
        DWORD oldProtect;
        if (force) {
            if (!SetMemoryProtect(addr, len, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                return false;
            }
        }
        SIZE_T readByte;
        bool success = true;
        if (ms_wow64.Wow64Operation(Get())) {
            HMODULE NtdllModule = GetModuleHandleW(L"ntdll.dll");
            pfnNtWow64QueryInformationProcess64 NtWow64QueryInformationProcess64 = (pfnNtWow64QueryInformationProcess64)GetProcAddress(NtdllModule, "NtWow64QueryInformationProcess64");
            pfnNtWow64WriteVirtualMemory64 NtWow64WriteVirtualMemory64 = (pfnNtWow64WriteVirtualMemory64)GetProcAddress(NtdllModule, "NtWow64WriteVirtualMemory64");
            if (!NT_SUCCESS(NtWow64WriteVirtualMemory64(Get(), addr, (PVOID)buf, len, NULL))) {
                success = false;
            }
        }
        else {
            if (Get() == kCurrentProcess) {
                memcpy((void*)addr, buf, len);
            }
            else if (!::WriteProcessMemory(Get(), (void*)addr, buf, len, &readByte)) {
                success = false;
            }
        }
        if (force) {
            SetMemoryProtect(addr, len, oldProtect, &oldProtect);
        }
        return true;
    }

    std::optional<uint64_t> WriteMemory(const void* buf, size_t len, DWORD protect = PAGE_READWRITE) {
        auto mem = AllocMemory(len, (DWORD)MEM_COMMIT, protect);
        if (!mem) {
            return {};
        }
        WriteMemory(mem.value(), buf, len);
        return mem;
    }

    bool SetMemoryProtect(uint64_t addr, size_t len, DWORD newProtect, DWORD* oldProtect) {
        bool success = false;
        if (ms_wow64.Wow64Operation(Get())) {
            success = ms_wow64.VirtualProtectEx64(Get(), (DWORD64)addr, len, newProtect, oldProtect);
        }
        else {
            success = ::VirtualProtectEx(Get(), (LPVOID)addr, len, newProtect, oldProtect);
        }
        return success;
    }

    std::optional<MemoryInfo> GetMemoryInfo(uint64_t addr) const {
        uint64_t size;
        MEMORY_BASIC_INFORMATION    memInfo = { 0 };
        MEMORY_BASIC_INFORMATION64    memInfo64 = { 0 };
        if (ms_wow64.Wow64Operation(Get())) {
            size = Geek::Wow64::VirtualQueryEx64(Get(), addr, &memInfo64, sizeof(memInfo64));
            if (size != sizeof(memInfo64)) { return {}; }
            return MemoryInfo(memInfo64);
        }
        else {
            size_t size = ::VirtualQueryEx(Get(), (PVOID)addr, &memInfo, sizeof(memInfo));
            if (size != sizeof(memInfo)) { return {}; }
            if (IsX86()) {
                return MemoryInfo(*(MEMORY_BASIC_INFORMATION32*)&memInfo);
            }
            else {
                return MemoryInfo(*(MEMORY_BASIC_INFORMATION64*)&memInfo);
            }
        }
    }

    std::optional<std::vector<MemoryInfo>> GetMemoryInfoList() const {
        std::vector<MemoryInfo> memory_block_list;

        memory_block_list.reserve(200);
        /*
        typedef struct _SYSTEM_INFO {
        union {
        DWORD dwOemId;
        struct {
        WORD wProcessorArchitecture;
        WORD wReserved;
        } DUMMYSTRUCTNAME;
        } DUMMYUNIONNAME;
        DWORD     dwPageSize;
        LPVOID    lpMinimumApplicationAddress;
        LPVOID    lpMaximumApplicationAddress;
        DWORD_PTR dwActiveProcessorMask;
        DWORD     dwNumberOfProcessors;
        DWORD     dwProcessorType;
        DWORD     dwAllocationGranularity;
        WORD        wProcessorLevel;
        WORD        wProcessorRevision;
        } SYSTEM_INFO, *LPSYSTEM_INFO;
        */

        uint64_t p = 0;
        MEMORY_BASIC_INFORMATION mem_info = { 0 };
        MEMORY_BASIC_INFORMATION64 mem_info64 = { 0 };
        while (true) {
            uint64_t size;
            if (ms_wow64.Wow64Operation(Get())) {
                size = Geek::Wow64::VirtualQueryEx64(Get(), p, &mem_info64, sizeof(mem_info64));
                if (size != sizeof(mem_info64)) { break; }
                memory_block_list.push_back(MemoryInfo{ mem_info64 });
                p += mem_info64.RegionSize;
            }
            else {
                size_t size = ::VirtualQueryEx(Get(), (PVOID)p, &mem_info, sizeof(mem_info));
                if (size != sizeof(mem_info)) { break; }
                if (IsX86()) {
                    memory_block_list.push_back(MemoryInfo{ *(MEMORY_BASIC_INFORMATION32*)&mem_info });
                }
                else {
                    memory_block_list.push_back(MemoryInfo{ *(MEMORY_BASIC_INFORMATION64*)&mem_info });
                }
                p += mem_info.RegionSize;
            }
            
        }
        return memory_block_list;
    }

    bool ScanMemoryInfoList(std::function<bool(uint64_t raw_addr, uint8_t* addr, size_t size)> callback, bool include_module = false) const {
        bool success = false;
        do {
            auto module_list_res = GetModuleInfoList();
            if (!module_list_res) {
                return false;
            }
            auto& module_list = module_list_res.value();
            auto vec_res = GetMemoryInfoList();
            if (!vec_res) {
                return false;
            }
            auto& vec = vec_res.value();
            size_t sizeSum = 0;

            for (int i = 0; i < vec.size(); i++) {
                if (vec[i].protect & PAGE_NOACCESS || !vec[i].protect) {
                    continue;
                }

                if (include_module == false) {
                    bool is_module = false;
                    for (int j = 0; j < module_list.size(); j++) {
                        if (vec[i].base >= module_list[j].base && vec[i].base < module_list[j].base + module_list[j].base) {
                            is_module = true;
                            break;
                        }
                    }
                    if (!(!is_module && vec[i].protect & PAGE_READWRITE && vec[i].state & MEM_COMMIT)) {
                        continue;
                    }
                }

                auto temp_buff = ReadMemory(vec[i].base, vec[i].size);
                if (!temp_buff) {
                    continue;
                }
                
                if (callback(vec[i].base, temp_buff.value().data(), temp_buff.value().size())) {
                    break;
                }
                sizeSum += vec[i].size;
            }
            success = true;
        } while (false);
        return success;
    }

        
    /*
    * Info
    */
    std::optional<std::wstring> GetCommandLineStr() {
        typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
            HANDLE ProcessHandle,
            DWORD ProcessInformationClass,
            PVOID ProcessInformation,
            DWORD ProcessInformationLength,
            PDWORD ReturnLength
            );
        
        if (IsX86()) {
            UNICODE_STRING32 commandLine;
            _NtQueryInformationProcess NtQuery = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
            if (!NtQuery) {
                return {};
            }

            PROCESS_BASIC_INFORMATION32 pbi;
            NTSTATUS isok = NtQuery(Get(), ProcessBasicInformation, &pbi, sizeof(RTL_USER_PROCESS_PARAMETERS32), NULL);
            if (!NT_SUCCESS(isok)) {
                return {};
            }

            PEB32 peb;
            RTL_USER_PROCESS_PARAMETERS32 upps;
            PRTL_USER_PROCESS_PARAMETERS32 rtlUserProcParamsAddress;
            if (!ReadMemory((uint64_t)&(((PEB32*)(pbi.PebBaseAddress))->ProcessParameters), &rtlUserProcParamsAddress, sizeof(rtlUserProcParamsAddress))) {
                return {};
            }

            if (!ReadMemory((uint64_t)&(rtlUserProcParamsAddress->CommandLine), &commandLine, sizeof(commandLine))) {
                return {};
            }

            std::wstring buf(commandLine.Length, L' ');
            if (!ReadMemory((uint64_t)commandLine.Buffer,
                (void*)buf.data(), commandLine.Length)) {
                return {};
            }
            return buf;
        }
        else {

            UNICODE_STRING64 commandLine;
            PROCESS_BASIC_INFORMATION64 pbi;
            HMODULE NtdllModule = GetModuleHandleA("ntdll.dll");
            if (ms_wow64.Wow64Operation(Get())) {
                pfnNtWow64QueryInformationProcess64 NtWow64QueryInformationProcess64 = (pfnNtWow64QueryInformationProcess64)GetProcAddress(NtdllModule, "NtWow64QueryInformationProcess64");
                if (!NT_SUCCESS(NtWow64QueryInformationProcess64(Get(), ProcessBasicInformation, &pbi, sizeof(pbi), NULL))) {
                    return {};
                }
            }
            else {
                pfnNtQueryInformationProcess NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(NtdllModule, "NtQueryInformationProcess");
                if (!NT_SUCCESS(NtQueryInformationProcess(Get(), ProcessBasicInformation, &pbi, sizeof(pbi), NULL))) {
                    return {};
                }
            }

            PEB64 peb;
            RTL_USER_PROCESS_PARAMETERS64 upps;
            PRTL_USER_PROCESS_PARAMETERS64 rtlUserProcParamsAddress;
            if (!ReadMemory((uint64_t) & (((PEB64*)(pbi.PebBaseAddress))->ProcessParameters), &rtlUserProcParamsAddress, sizeof(rtlUserProcParamsAddress))) {
                return {};
            }

            if (!ReadMemory((uint64_t) & (rtlUserProcParamsAddress->CommandLine), &commandLine, sizeof(commandLine))) {
                return {};
            }

            std::wstring buf(commandLine.Length, L' ');
            if (!ReadMemory((uint64_t)commandLine.Buffer,
                (void*)buf.data(), commandLine.Length)) {
                return {};
            }
            return buf;
        }
    }


        
    /*
    * Run
    */

    std::optional<uint16_t> LockAddress(uint64_t addr) {
        uint16_t instr;
        if (!ReadMemory(addr, &instr, 2)) {
            return {};
        }
        unsigned char jmpSelf[] = { 0xeb, 0xfe };
        if (!WriteMemory(addr, jmpSelf, 2, true)) {
            return {};
        }
        return instr;
    }

    bool UnlockAddress(uint64_t addr, uint16_t instr) {
        return WriteMemory(addr, &instr, 2, true);
    }

    /*
    * Thread
    */
    std::optional<Thread> CreateThread(uint64_t start_routine, uint64_t parameter, DWORD dwCreationFlags = 0 /*CREATE_SUSPENDED*/) {
        DWORD thread_id = 0;
        HANDLE thread_handle = NULL;
        if (IsCur()) {
            thread_handle = ::CreateThread(NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(start_routine), reinterpret_cast<PVOID64>(parameter), dwCreationFlags, &thread_id);
        }
        else {
            if (ms_wow64.Wow64Operation(Get())) {
                auto ntdll64 = ms_wow64.GetNTDLL64();
                auto RtlCreateUserThread = ms_wow64.GetProcAddress64(ntdll64, "RtlCreateUserThread");
                auto ntdll_RtlExitThread = ms_wow64.GetProcAddress64(ntdll64, "RtlExitUserThread");

                unsigned char shell_code[] = {
                    0x48, 0x89, 0x4c, 0x24, 0x08,                               // mov       qword ptr [rsp+8],rcx 
                    0x57,                                                       // push      rdi
                    0x48, 0x83, 0xec, 0x20,                                     // sub       rsp,20h
                    0x48, 0x8b, 0xfc,                                           // mov       rdi,rsp
                    0xb9, 0x08, 0x00, 0x00, 0x00,                               // mov       ecx,8
                    0xb8, 0xcc, 0xcc, 0xcc, 0xcc,                               // mov       eac,0CCCCCCCCh
                    0xf3, 0xab,                                                 // rep stos  dword ptr [rdi]
                    0x48, 0x8b, 0x4c, 0x24, 0x30,                               // mov       rcx,qword ptr [__formal]
                    0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rcx,   parameter
                    0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rax,0 
                    0xff, 0xd0,                                                 // call      rax    start_routine
                    0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rcx,0
                    0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rax,0
                    0xff, 0xd0                                                  // call      rax
                    
                };

                auto buf_addr = AllocMemory(size_t{ 4096 }, DWORD{ MEM_RESERVE | MEM_COMMIT }, PAGE_EXECUTE_READWRITE);
                if (!buf_addr) {
                    return {};
                }

                //r8
                memcpy(shell_code + 32, &parameter, sizeof(parameter));

                memcpy(shell_code + 42, &start_routine, sizeof(start_routine));

                //RtlExitUserThread
                memcpy(shell_code + 64, &ntdll_RtlExitThread, sizeof(DWORD64));
                size_t write_size = 0;

                if (!WriteMemory(*buf_addr, shell_code, sizeof(shell_code))) {
                    FreeMemory(*buf_addr);
                    return {};
                }

                struct {
                    DWORD64 UniqueProcess;
                    DWORD64 UniqueThread;
                } client_id { 0 };

                auto error = ms_wow64.X64Call(RtlCreateUserThread, 10,
                    reinterpret_cast<DWORD64>(Get()), 
                    static_cast<DWORD64>(NULL), static_cast<DWORD64>(FALSE),
                    static_cast<DWORD64>(0), static_cast<DWORD64>(NULL), static_cast<DWORD64>(NULL),
                    static_cast<DWORD64>(*buf_addr), static_cast<DWORD64>(0),
                    reinterpret_cast<DWORD64>(&thread_handle),
                    reinterpret_cast<DWORD64>(&client_id));
                
                if (thread_handle) {
                    ::WaitForSingleObject(thread_handle, INFINITE);
                }

                FreeMemory(*buf_addr);
                if (!NT_SUCCESS(error)) {
                    return {};
                }
            }
            else {
                thread_handle = ::CreateRemoteThread(Get(), NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(start_routine), reinterpret_cast<PVOID64>(parameter), dwCreationFlags, &thread_id);
            }
        }
        if (thread_handle == NULL) {
            return {};
        }
        return Thread{ thread_handle };
    }

    std::optional<uint16_t> BlockThread(Thread* thread) {
        if (!thread->Suspend()) {
            return {};
        }
        unsigned char jmpSelf[] = { 0xeb, 0xfe };
        uint64_t ip;
        if (IsX86()) {
            _CONTEXT32 context;
            GetThreadContext(thread, context);
            ip = context.Eip;
        }
        else {
            _CONTEXT64 context;
            GetThreadContext(thread, context);
            ip = context.Rip;
        }
        auto old_instr = LockAddress(ip);
        thread->Resume();
        return old_instr;
    }

    bool ResumeBlockedThread(Thread* thread, uint16_t instr) {
        if (!thread->Suspend()) {
            return false;
        }
        uint16_t oldInstr;
        uint64_t ip;
        if (IsX86()) {
            _CONTEXT32 context;
            GetThreadContext(thread, context);
            ip = context.Eip;
        }
        else {
            _CONTEXT64 context;
            GetThreadContext(thread, context);
            ip = context.Rip;
        }
        auto success = UnlockAddress(ip, instr);
        thread->Resume();
        return success;
    }

    bool IsTheOwningThread(Thread* thread) {
        return GetProcessIdOfThread(thread) == GetId();
    }


    bool GetThreadContext(Thread* thread, _CONTEXT32& context, DWORD flags = CONTEXT64_CONTROL | CONTEXT64_INTEGER) {
        if (IsX86()) {
            return false;
        }
        bool success;
        context.ContextFlags = flags;
        if (!CurIsX86()) {
            success = ::Wow64GetThreadContext(thread->Get(), &context);
        }
        else {
            success = ::GetThreadContext(thread->Get(), reinterpret_cast<CONTEXT*>(&context));
        }
        return success;
    }

    bool GetThreadContext(Thread* thread, _CONTEXT64& context, DWORD flags = CONTEXT64_CONTROL | CONTEXT64_INTEGER) {
        if (IsX86()) {
            return false;
        }
        bool success;
        context.ContextFlags = flags;
        if (ms_wow64.Wow64Operation(Get())) {
            success = ms_wow64.GetThreadContext64(thread->Get(), &context);
        }
        else {
            success = ::GetThreadContext(thread->Get(), reinterpret_cast<CONTEXT*>(&context));
        }
        return success;
    }

    bool SetThreadContext(Thread* thread, _CONTEXT32& context, DWORD flags = CONTEXT64_CONTROL | CONTEXT64_INTEGER) {
        if (!IsX86()) {
            return false;
        }
        bool success; 
        context.ContextFlags = flags;
        if (!CurIsX86()) {
            success = ::Wow64SetThreadContext(thread->Get(), &context);
        }
        else {
            success = ::SetThreadContext(thread->Get(), reinterpret_cast<CONTEXT*>(&context));
        }
        return success;
    }

    bool SetThreadContext(Thread* thread, _CONTEXT64& context, DWORD flags = CONTEXT64_CONTROL | CONTEXT64_INTEGER) {
        if (!IsX86()) {
            return false;
        }
        bool success;
        context.ContextFlags = flags;
        if (ms_wow64.Wow64Operation(Get())) {
            success = ms_wow64.SetThreadContext64(thread->Get(), &context);
        }
        else {
            success = ::SetThreadContext(thread->Get(), reinterpret_cast<CONTEXT*>(&context));
        }
        return success;
    }



    bool WaitExit(DWORD dwMilliseconds = INFINITE) {
        if (IsCur()) {
            return false;
        }
        return WaitForSingleObject(Get(), dwMilliseconds) == WAIT_OBJECT_0;
    }

    std::optional<DWORD> GetExitCode() {
        DWORD code;
        if (!GetExitCodeProcess(Get(), &code)) {
            return {};
        }
        return code;
    }

    /*
    * Image
    */
    std::optional<uint64_t> LoadLibraryFromImage(Image* image, bool exec_tls_callback = true, bool call_dll_entry = true, uint64_t init_parameter = 0, bool skip_not_loaded = false, bool zero_pe_header = true, bool entry_call_sync = true) {
        if (IsX86() != image->IsPE32()) {
            return 0;
        }
        auto image_base_res = AllocMemory(image->GetImageSize(), (DWORD)MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!image_base_res) return {};
        auto& image_base = *image_base_res;
        bool success = false;
        do {
            if (!image->RepairRepositionTable(image_base)) {
                break;
            }
            if (!RepairImportAddressTable(image, skip_not_loaded)) {
                break;
            }
            auto image_buf = image->SaveToImageBuf(image_base, zero_pe_header);
            if (!WriteMemory(image_base, image_buf.data(), image_buf.size())) {
                break;
            }
            /*
            * tls的调用必须同步，否则出现并发执行的问题
            */
            if (exec_tls_callback) {
                ExecuteTls(image, image_base);
            }
            if (call_dll_entry) {
                CallEntryPoint(image, image_base, init_parameter, entry_call_sync);
            }
            success = true;
        } while (false);
        if (success == false && image_base) {
            FreeMemory(image_base);
            image_base = 0;
        }
        image->SetMemoryImageBase(image_base);
        return image_base;
    }

    std::optional<Image> LoadImageFromImageBase(uint64_t image_base) {
        if (IsCur()) {
            return Image::LoadFromImageBuf((void*)image_base, image_base);
        }
        else {
            auto module_info = GetModuleInfoByModuleBase(image_base);
            if (!module_info) return {};
            auto buf = ReadMemory(image_base, module_info.value().size);
            if (!buf) {
                return {};
            }
            return Image::LoadFromImageBuf(buf->data(), image_base);
        }
    }

    bool FreeLibraryFromImage(Image* image, bool call_dll_entry = true) {
        if (call_dll_entry) {
            //if (!CallEntryPoint(image, image->GetMemoryImageBase(), DLL_PROCESS_DETACH)) {
            //    return false;
            //}
        }
        FreeMemory(image->GetMemoryImageBase());
        return true;
    }

    bool FreeLibraryFromBase(uint64_t base, bool call_dll_entry = true) {
        auto module_info = GetModuleInfoByModuleBase(base);
        if (!module_info) {
            return false;
        }
        auto image = GetImageByModuleInfo(*module_info);
        if (!image) {
            return false;
        }
        return FreeLibraryFromImage(&*image, call_dll_entry);
    }

    /*
    * library
    */
    std::optional<uint64_t> LoadLibrary(std::wstring_view lib_name, bool sync = true) {
        if (IsCur()) {
            auto addr = ::LoadLibraryW(lib_name.data());
            if (!addr) {
                return {};
            }
            return reinterpret_cast<uint64_t>(addr);
        }

        auto module = GetModuleInfoByModuleName(lib_name);
        if (module) {
            return module.value().base;
        }

        uint64_t addr = NULL;
        
        if (ms_wow64.Wow64Operation(Get())) {
            auto ntdll64 = ms_wow64.GetNTDLL64();
            auto LdrLoadDll = ms_wow64.GetProcAddress64(ntdll64, "LdrLoadDll");
            UNICODE_STRING64 us64;
            auto str_len = lib_name.size() * 2;
            if (str_len % 8 != 0) {
                str_len += 8 - str_len % 8;
            }
            auto len = 0x1000 + str_len + sizeof(UNICODE_STRING64) + sizeof(DWORD64);
            auto lib_name_buf_res = AllocMemory(NULL, len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (!lib_name_buf_res) {
                return {};
            }
            auto lib_name_buf = *lib_name_buf_res;
            lib_name_buf += 0x1000;
            do {
                if (!WriteMemory(lib_name_buf, lib_name.data(), len)) {
                    break;
                }
                auto unicode_str_addr = lib_name_buf + str_len;
               
                auto raw_str_len = lib_name.size() * 2;
                if (!WriteMemory(uint64_t{ unicode_str_addr + reinterpret_cast<uint64_t>(&((UNICODE_STRING64*)0)->Length) }, &raw_str_len, 2)) {
                    break;
                }
                if (!WriteMemory(uint64_t{ unicode_str_addr + reinterpret_cast<uint64_t>(&((UNICODE_STRING64*)0)->MaximumLength) }, &raw_str_len, 2)) {
                    break;
                }
                if (!WriteMemory(uint64_t{ unicode_str_addr + reinterpret_cast<uint64_t>(&((UNICODE_STRING64*)0)->Buffer) }, &lib_name_buf, 8)) {
                    break;
                }

                Call(lib_name_buf - 0x1000, LdrLoadDll, { 0, 0, unicode_str_addr, unicode_str_addr + sizeof(UNICODE_STRING64) }, &addr, Process::CallConvention::kStdCall, sync);
            } while (false);
            if (sync && lib_name_buf) {
                FreeMemory(lib_name_buf);
            }

        }
        else {
            auto len = 0x1000 + lib_name.size() * 2 + 2;
            auto lib_name_buf_res = AllocMemory(NULL, len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (!lib_name_buf_res) {
                return {};
            }
            auto lib_name_buf = *lib_name_buf_res;
            lib_name_buf += 0x1000;
            do {
                if (!WriteMemory(lib_name_buf, lib_name.data(), len)) {
                    break;
                }
                Call(lib_name_buf - 0x1000, (uint64_t)::LoadLibraryW, { lib_name_buf }, &addr, Process::CallConvention::kStdCall, sync);
            } while (false);
            if (sync && lib_name_buf) {
                FreeMemory(lib_name_buf);
            }
        }
        
        return addr;
    }

    bool FreeLibrary(uint64_t module_base) {
        if (IsCur()) {
            return ::FreeLibrary((HMODULE)module_base);
        }
        do {
            auto thread = CreateThread((uint64_t)::FreeLibrary, module_base);
            if (!thread) {
                return false;
            }
            thread.value().WaitExit(INFINITE);
        } while (false);
    }

    std::optional<Image> GetImageByModuleInfo(const Geek::ModuleInfo& info) {
        auto buf = ReadMemory(info.base, info.size);
        if (!buf) return {};
        return Image::LoadFromImageBuf(buf->data(), info.base);
    }

    std::optional<uint64_t> GetExportProcAddress(Image* image, const char* func_name) {
        uint32_t export_rva;
        if (reinterpret_cast<uintptr_t>(func_name) <= 0xffff) {
            export_rva = image->GetExportRvaByOrdinal(reinterpret_cast<uint16_t>(func_name));
        }
        else {
            export_rva = image->GetExportRvaByName(func_name);
        }
        // 可能返回一个字符串，需要二次加载
        // 对应.def文件的EXPORTS后加上 MsgBox = user32.MessageBoxA 的情况
        uint64_t va = (uint64_t)image->GetMemoryImageBase() + export_rva;
        auto export_directory = (uint64_t)image->GetMemoryImageBase() + image->GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        auto export_directory_size = image->GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        // 还在导出表范围内，是这样子的字符串：NTDLL.RtlAllocateHeap
        if (va > export_directory && va < export_directory + export_directory_size) {
            std::string full_name = (char*)image->RvaToPoint(export_rva);
            auto offset = full_name.find(".");
            auto dll_name = full_name.substr(0, offset);
            auto func_name = full_name.substr(offset + 1);
            if (!dll_name.empty() && !func_name.empty()) {
                auto image_base = LoadLibrary(Geek::String::AnsiToUtf16le(dll_name).c_str());
                if (image_base == 0) return {};
                auto import_image = LoadImageFromImageBase(image_base.value());
                if (!import_image) return {};
                auto va_res = GetExportProcAddress(&import_image.value(), func_name.c_str());
                if (!va_res) return {};
                return va_res.value();
            }
        }
        return va;
    }

    
    /*
    * call
    */

    class CallPage {
    public:
        CallPage(Process* process)
            : process_(process) {
            auto res = process->AllocMemory(NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (res) {
                exec_page_ = *res;
                std::array<uint8_t, 0x1000> tmp{ 0 };
                process->WriteMemory(exec_page_, tmp.data(), tmp.size());
            }
        }

        ~CallPage() {
            Close();
        }

        CallPage(const CallPage&) = delete;
        void operator=(const CallPage&) = delete;

        CallPage(CallPage&& rv) {
            Close();
            process_ = rv.process_;
            exec_page_ = rv.exec_page_;
            rv.exec_page_ = 0;
        }

        uint64_t exec_page() const { return exec_page_; }


    private:
        void Close() {
            if (exec_page_) {
                process_->FreeMemory(exec_page_);
                exec_page_ = 0;
            }
        }
    private:
        Process* process_;
        uint64_t exec_page_ = 0;
    };

    // 注：如果调用的是X86，par_list传递uint64_t会被截断为uint32_t
    enum class CallConvention {
        kCdeclCall,
        kThisCall,
        kStdCall,
        kFastCall,
    };
    bool CallGenerateCode(uint64_t exec_page, uint64_t call_addr
        , const std::initializer_list<uint64_t>& par_list = {}
        , uint64_t* ret_value = nullptr
        , CallConvention call_convention = CallConvention::kStdCall) {
        constexpr int32_t exec_offset = 0x100;

        std::array<uint8_t, 0x1000> temp_data = { 0 };
        uint8_t* temp = temp_data.data();
        if (IsCur()) {
            temp = reinterpret_cast<uint8_t*>(exec_page);
        }

        if (IsX86()) {
            int32_t not_push_count = 0;
            switch (call_convention) {
            case CallConvention::kFastCall: {
                not_push_count = 2;
                break;
            }
            case CallConvention::kThisCall: {
                not_push_count = 1;
                break;
            }
            }

            int32_t i = exec_offset;

            const auto* par_list_ = par_list.begin();
            for (int j = par_list.size() - 1; j >= not_push_count; j--) {
                temp[i++] = 0x68;        // push par[j]
                *(uint32_t*)&temp[i] = par_list_[j];
                i += 4;
            }

            // mov reg, par_list[j]
            uint8_t reg_code[] = {
                0xb9,
                0xba,
            };
            for (int j = not_push_count - 1; j >= 0; j--) {
                temp[i++] = reg_code[j];
                *((uint32_t*)&temp[i]) = par_list_[j];
                i += 4;
            }

            temp[i++] = 0xb8;        // mov eax, entry_point
            *(uint32_t*)&temp[i] = (uint32_t)call_addr;
            i += 4;

            temp[i++] = 0xff;        // call eax
            temp[i++] = 0xd0;

            switch (call_convention) {
            case CallConvention::kFastCall:
            case CallConvention::kStdCall: {
                break;
            }
            case CallConvention::kCdeclCall:
            case CallConvention::kThisCall: {
                temp[i++] = 0x83;        // add esp, par_list.size() * 4
                temp[i++] = 0xc4;
                temp[i++] = (par_list.size() - not_push_count) * 4;
                break;
            }
            }

            // mov [exec_page], eax
            temp[i++] = 0xa3;
            *(uint32_t*)&temp[i] = (uint32_t)exec_page;
            i += 4;

            // xor eax, eax
            temp[i++] = 0x31;
            temp[i++] = 0xc0;

            if (IsCur()) {
                temp[i++] = 0xc3;
            }
            else {
                // 创建线程需要平栈
                temp[i++] = 0xc2;        // ret 4
                *(uint16_t*)&temp[i] = 4;
                i += 2;
            }
        }
        else {
            int32_t i = exec_offset;      // 返回值的位置
            int8_t stack_size = par_list.size() * 8;

            if ((stack_size & 8) == 0) {
                stack_size += 8;
            }

            if (stack_size < 0x28) {
                stack_size = 0x28;
            }

            // 构建栈帧
            temp[i++] = 0x48;        // sub rsp, size
            temp[i++] = 0x83;
            temp[i++] = 0xec;
            temp[i++] = stack_size;

            uint16_t reg_code[] = {
                0xb948,
                0xba48,
                0xb849,
                0xb949,
            };
            const auto* par_list_ = par_list.begin();
            for (int j = 0; j < std::min(size_t{ 4 }, par_list.size()); j++) {
                // 寄存器传参
                // mov reg, par[j]
                *((uint16_t*)&temp[i]) = reg_code[j];
                i += 2;

                *((uint64_t*)&temp[i]) = par_list_[j];
                i += 8;
            }

            for (int j = 4; j < par_list.size(); j++) {
                // 栈传参
                // mov rax, par[j]
                temp[i++] = 0x48;
                temp[i++] = 0xb8;
                *((uint64_t*)&temp[i]) = par_list_[j];
                i += 8;
                // mov [rsp+ j * 8], rax
                temp[i++] = 0x48;
                temp[i++] = 0x89;
                temp[i++] = 0x44;
                temp[i++] = 0x24;
                temp[i++] = j * 8;

            }

            temp[i++] = 0x48;        // mov rax, call_addr
            temp[i++] = 0xb8;
            *(uint64_t*)&temp[i] = (uint64_t)call_addr;
            i += 8;
            // call rax
            temp[i++] = 0xff;
            temp[i++] = 0xd0;

            // 还原栈帧
            temp[i++] = 0x48;
            temp[i++] = 0x83;
            temp[i++] = 0xc4;
            temp[i++] = stack_size;

            // mov rcx, exec_page
            temp[i++] = 0x48;
            temp[i++] = 0xb9;
            *(uint64_t*)&temp[i] = (uint64_t)exec_page;
            i += 8;
            // mov [rcx], rax
            temp[i++] = 0x48;
            temp[i++] = 0x89;
            temp[i++] = 0x01;

            // xor rax, rax
            temp[i++] = 0x48;
            temp[i++] = 0x31;
            temp[i++] = 0xc0;

            temp[i++] = 0xc3;        // ret
        }

        if (!IsCur()) {
            if (!WriteMemory(exec_page, temp, 0x1000)) {
                return false;
            }
        }
        return true;
    }
    bool Call(uint64_t exec_page, uint64_t call_addr
        , const std::initializer_list<uint64_t>& par_list = {}
        , uint64_t* ret_value = nullptr
        , CallConvention call_convention = CallConvention::kStdCall
        , bool sync = true
        , bool init_exec_page = true) {

        constexpr int32_t exec_offset = 0x100;

        if (init_exec_page) {
            if (!CallGenerateCode(exec_page, call_addr, par_list, ret_value)) {
                return false;
            }
        }
        
        bool success = false;
        do {
            if (sync && IsCur()) {
                using Func = uint64_t(*)();
                Func func = reinterpret_cast<Func>(exec_page + exec_offset);
                uint64_t ret = func();
                if (ret_value) {
                    *ret_value = ret;
                }
            }
            else {
                auto thread = CreateThread(exec_page + exec_offset, NULL);
                if (!thread) {
                    break;
                }

                if (sync) {
                    if (!thread.value().WaitExit()) {
                        break;
                    }
                    if (ret_value) {
                        *ret_value = 0;
                        ReadMemory(exec_page, ret_value, exec_offset);
                    }
                }
                else {
                    if (ret_value) {
                        *ret_value = 0;
                    }
                }
            }
            success = true;
        }
        while (false);
        return success;
    }
    bool Call(uint64_t call_addr
        , const std::initializer_list<uint64_t>& par_list = {}
        , uint64_t* ret_value = nullptr
        , CallConvention call_convention = CallConvention::kStdCall) {
        uint64_t exec_page = 0;
        bool init_exec_page = true;
        if (IsCur()) {
            // 当前进程的调用才使用优化策略
            // 跨进程调用的主要开销不在这里
            thread_local std::unordered_map<uint64_t, CallPage> map_;
            auto iter = map_.find(call_addr);
            if (iter == map_.end()) {
                auto page = CallPage(this);
                exec_page = page.exec_page();
                map_.insert(std::make_pair(call_addr, std::move(page)));
            }
            else {
                exec_page = iter->second.exec_page();
                init_exec_page = false;
            }
        }
        // thread_local CallPage call_page(this);
        // exec_page = call_page.exec_page();

        if (!exec_page) {
            return false;
        }
        bool success = Call(exec_page, call_addr, par_list, ret_value, call_convention, true, true);
        return success;
    }

    struct CallContextX86 {
        uint32_t eax = 0;
        uint32_t ecx = 0;
        uint32_t edx = 0;
        uint32_t ebx = 0;
        uint32_t esi = 0;
        uint32_t edi = 0;
        int32_t balanced_esp = 0;
        std::initializer_list<uint32_t> stack;  // 目前调用完，不会将栈拷贝回来
    };
    bool CallGenerateCode(uint64_t exec_page, uint64_t call_addr, CallContextX86* context) {

        constexpr int32_t save_call_addr_offset = 0x0;
        constexpr int32_t context_offset = 0x64;
        constexpr int32_t exec_offset = 0x100;

        std::array<uint8_t, 0x1000> temp_data = { 0 };
        uint8_t* temp = temp_data.data();
        if (IsCur()) {
            temp = reinterpret_cast<uint8_t*>(exec_page);
        }

        // *(uint32_t*)&temp[save_call_addr_offset] = (uint32_t)call_addr;

        int32_t i = exec_offset;

        // 保存非易变寄存器
        // push ebx
        temp[i++] = 0x53;
        // push ebp
        temp[i++] = 0x55;
        // push esi
        temp[i++] = 0x56;
        // push edi
        temp[i++] = 0x57;

        // mov eax, call_addr
        temp[i++] = 0xb8;
        *(uint32_t*)&temp[i] = (uint32_t)call_addr;
        i += 4;
        // mov [exec_page], eax
        temp[i++] = 0xa3;
        *(uint32_t*)&temp[i] = (uint32_t)exec_page;
        i += 4;

        // mov eax, context.eax
        temp[i++] = 0xb8;
        *((uint32_t*)&temp[i]) = context->eax;
        i += 4;
        // mov ecx, context.ecx
        temp[i++] = 0xb9;
        *((uint32_t*)&temp[i]) = context->ecx;
        i += 4;
        // mov edx, context.edx
        temp[i++] = 0xba;
        *((uint32_t*)&temp[i]) = context->edx;
        i += 4;
        // mov ebx, context.ebx
        temp[i++] = 0xbb;
        *((uint32_t*)&temp[i]) = context->ebx;
        i += 4;
        // mov esi, context.esi
        temp[i++] = 0xbe;
        *((uint32_t*)&temp[i]) = context->esi;
        i += 4;
        // mov edi, context.edi
        temp[i++] = 0xbf;
        *((uint32_t*)&temp[i]) = context->edi;
        i += 4;

        for (int j = context->stack.size() - 1; j >= 0; j--) {
            const auto* stack = context->stack.begin();
            temp[i++] = 0x68;        // push par[j]
            *(uint32_t*)&temp[i] = stack[j];
            i += 4;
        }

        // call [exec_page]
        temp[i++] = 0xff;
        temp[i++] = 0x15;
        *((uint32_t*)&temp[i]) = exec_page;
        i += 4;

        // 暂时不做栈拷贝
        // add esp, context.balanced_esp
        temp[i++] = 0x81;
        temp[i++] = 0xc4;
        *((uint32_t*)&temp[i]) = context->balanced_esp;
        i += 4;

        // 不能直接访问，可能是其他进程的exec_page
        CallContextX86* ret_context = reinterpret_cast<CallContextX86*>(exec_page + context_offset);

        // mov [ret_context.eax], eax
        temp[i++] = 0xa3;
        *((uint32_t*)&temp[i]) = reinterpret_cast<uint32_t>(&ret_context->eax);
        i += 4;

        // mov [ret_context.ecx], ecx
        temp[i++] = 0x89;
        temp[i++] = 0x0d;
        *((uint32_t*)&temp[i]) = reinterpret_cast<uint32_t>(&ret_context->ecx);
        i += 4;

        // mov [ret_context.edx], edx
        temp[i++] = 0x89;
        temp[i++] = 0x15;
        *((uint32_t*)&temp[i]) = reinterpret_cast<uint32_t>(&ret_context->edx);
        i += 4;

        // mov [ret_context.ebx], ebx
        temp[i++] = 0x89;
        temp[i++] = 0x1d;
        *((uint32_t*)&temp[i]) = reinterpret_cast<uint32_t>(&ret_context->ebx);
        i += 4;

        // mov [ret_context.esi], esi
        temp[i++] = 0x89;
        temp[i++] = 0x35;
        *((uint32_t*)&temp[i]) = reinterpret_cast<uint32_t>(&ret_context->esi);
        i += 4;

        // mov [ret_context.edi], edi
        temp[i++] = 0x89;
        temp[i++] = 0x3d;
        *((uint32_t*)&temp[i]) = reinterpret_cast<uint32_t>(&ret_context->edi);
        i += 4;

        // pop edi
        temp[i++] = 0x5f;
        // pop esi
        temp[i++] = 0x5e;
        // pop ebp
        temp[i++] = 0x5d;
        // pop ebx
        temp[i++] = 0x5b;

        if (IsCur()) {
            temp[i++] = 0xc3;
        }
        else {
            // 创建线程需要平栈
            temp[i++] = 0xc2;        // ret 4
            *(uint16_t*)&temp[i] = 4;
            i += 2;
        }

        if (!IsCur()) {
            if (!WriteMemory(exec_page, temp, 0x1000)) {
                return false;
            }
        }
        return true;
    }
    bool Call(uint64_t exec_page, uint64_t call_addr, CallContextX86* context, bool sync = true, bool init_exec_page = true) {
        if (!IsX86()) {
            return false;
        }
        // 调用地址(4字节), ret_call_context_x86
        constexpr int32_t context_offset = 0x64;
        constexpr int32_t exec_offset = 0x100;

        if (init_exec_page) {
            if (!CallGenerateCode(exec_page, call_addr, context)) {
                return false;
            }
        }

        bool success = false;
        do {
            if (sync && IsCur()) {
                using Func = uint64_t(*)();
                Func func = reinterpret_cast<Func>(exec_page + exec_offset);
                uint64_t ret = func();
                ReadMemory(exec_page + context_offset, context, offsetof(CallContextX86, balanced_esp));
            }
            else {
                auto thread = CreateThread(exec_page + exec_offset, NULL);
                if (!thread) {
                    break;
                }

                if (sync) {
                    if (!thread.value().WaitExit()) {
                        break;
                    }
                    ReadMemory(exec_page + context_offset, context, sizeof(*context) - offsetof(CallContextX86, stack));
                }
            }
            success = true;
        } while (false);
        return success;
    }
    bool Call(uint64_t call_addr, CallContextX86* context, bool sync = true) {
        uint64_t exec_page = 0;
        bool init_exec_page = true;
        if (IsCur()) {
            // 当前进程的调用才使用优化策略
            // 跨进程调用的主要开销不在这里
            thread_local std::unordered_map<uint64_t, CallPage> map_;
            auto iter = map_.find(call_addr);
            if (iter == map_.end()) {
                auto page = CallPage(this);
                exec_page = page.exec_page();
                map_.insert(std::make_pair(call_addr, std::move(page)));
            }
            else {
                exec_page = iter->second.exec_page();
                init_exec_page = false;
            }
        }
        if (!exec_page) {
            return false;
        }
        bool success = Call(exec_page, call_addr, context, sync, init_exec_page);
        return success;
    }

private:
    template<typename IMAGE_THUNK_DATA_T>
    bool RepairImportAddressTableFromModule(Image* image, _IMAGE_IMPORT_DESCRIPTOR* import_descriptor, uint64_t import_image_base, bool skip_not_loaded) {
        IMAGE_THUNK_DATA_T* import_name_table = (IMAGE_THUNK_DATA_T*)image->RvaToPoint(import_descriptor->OriginalFirstThunk);
        IMAGE_THUNK_DATA_T* import_address_table = (IMAGE_THUNK_DATA_T*)image->RvaToPoint(import_descriptor->FirstThunk);
        Image import_image;
        if (import_image_base) {
            auto import_image_res = LoadImageFromImageBase(import_image_base);
            if (!import_image_res) {
                return false;
            }
            import_image = std::move(*import_image_res);
        }
        else if (!skip_not_loaded) {
            return false;
        }
        for (; import_name_table->u1.ForwarderString; import_name_table++, import_address_table++) {
            if (!import_image_base) {
                import_address_table->u1.Function = import_address_table->u1.Function = 0x1234567887654321;
                continue;
            }
            uint32_t export_rva;
            if (import_name_table->u1.Ordinal >> (sizeof(import_name_table->u1.Ordinal) * 8 - 1) == 1) {
                auto export_addr = GetExportProcAddress(&import_image, (char*)((import_name_table->u1.Ordinal << 1) >> 1));
                if (!export_addr) return false;
                import_address_table->u1.Function = export_addr.value();
            }
            else {
                IMAGE_IMPORT_BY_NAME* func_name = (IMAGE_IMPORT_BY_NAME*)image->RvaToPoint(import_name_table->u1.AddressOfData);
                auto export_addr = GetExportProcAddress(&import_image, (char*)func_name->Name);
                if (!export_addr) return false;
                import_address_table->u1.Function = export_addr.value();
            }
            //import_address_table->u1.Function = import_module_base + export_rva;
        }
        return true;
    }
public:
    bool RepairImportAddressTable(Image* image, bool skip_not_loaded = false) {
        auto import_descriptor = (_IMAGE_IMPORT_DESCRIPTOR*)image->RvaToPoint(image->GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        if (import_descriptor == nullptr) {
            return false;
        }
        for (; import_descriptor->FirstThunk; import_descriptor++) {
            if(import_descriptor->OriginalFirstThunk == NULL) import_descriptor->OriginalFirstThunk = import_descriptor->FirstThunk;
            char* import_module_name = (char*)image->RvaToPoint(import_descriptor->Name);
            auto import_module_base_res = LoadLibrary(Geek::String::AnsiToUtf16le(import_module_name).c_str());
            if (!import_module_base_res) return false;
            if (image->IsPE32()) {
                if (!RepairImportAddressTableFromModule<IMAGE_THUNK_DATA32>(image, import_descriptor, import_module_base_res.value(), skip_not_loaded)) {
                    return false;
                }
            }
            else {
                if (!RepairImportAddressTableFromModule<IMAGE_THUNK_DATA64>(image, import_descriptor, import_module_base_res.value(), skip_not_loaded)) {
                    return false;
                }
            }
        }
        return true;
    }

    /*
    * TLS
    */
private:
    // PIMAGE_TLS_CALLBACK
    typedef VOID(NTAPI* PIMAGE_TLS_CALLBACK32)(uint32_t DllHandle, DWORD Reason, PVOID Reserved);
    typedef VOID(NTAPI* PIMAGE_TLS_CALLBACK64)(uint64_t DllHandle, DWORD Reason, PVOID Reserved);
public:
    bool ExecuteTls(Image* image, uint64_t image_base) {
        auto tls_dir = (IMAGE_TLS_DIRECTORY*)image->RvaToPoint(image->GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        if (tls_dir == nullptr) {
            return false;
        }
        PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)tls_dir->AddressOfCallBacks;
        if (callback) {
            while (true) {
                if (IsCur()) {
                    if (!*callback) {
                        break;
                    }
                    if (image->IsPE32()) {
                        PIMAGE_TLS_CALLBACK32 callback32 = *(PIMAGE_TLS_CALLBACK32*)callback;
                        callback32((uint32_t)image_base, DLL_PROCESS_ATTACH, NULL);
                    }
                    else {
                        PIMAGE_TLS_CALLBACK64 callback64 = *(PIMAGE_TLS_CALLBACK64*)callback;
                        callback64(image_base, DLL_PROCESS_ATTACH, NULL);
                    }
                }
                else {
                    if (image->IsPE32()) {
                        PIMAGE_TLS_CALLBACK32 callback32;
                        if (!ReadMemory((uint64_t)callback, &callback32, sizeof(PIMAGE_TLS_CALLBACK32))) {
                            return false;
                        }
                        Call(image_base, (uint64_t)callback32, { image_base, DLL_PROCESS_ATTACH , NULL });
                    }
                    else {
                        PIMAGE_TLS_CALLBACK64 callback64;
                        if (!ReadMemory((uint64_t)callback, &callback64, sizeof(PIMAGE_TLS_CALLBACK64))) {
                            return false;
                        }
                        Call(image_base, (uint64_t)callback64, { image_base, DLL_PROCESS_ATTACH , NULL });
                    }
                }
                callback++;
            }
        }
        return true;
    }

    /*
    * Running
    */
private:
    typedef BOOL(WINAPI* DllEntryProc32)(uint32_t hinstDLL, DWORD fdwReason, uint32_t lpReserved);
    typedef BOOL(WINAPI* DllEntryProc64)(uint64_t hinstDLL, DWORD fdwReason, uint64_t lpReserved);
    typedef int (WINAPI* ExeEntryProc)(void);
public:
    bool CallEntryPoint(Image* image, uint64_t image_base, uint64_t init_parameter = 0, bool sync = true) {
        if (IsCur()) {
            uint32_t rva = image->GetEntryPoint();
            if (image->m_file_header->Characteristics & IMAGE_FILE_DLL) {
                if (image->IsPE32()) {
                    DllEntryProc32 DllEntry = (DllEntryProc32)(image_base + rva);
                    DllEntry((uint32_t)image_base, DLL_PROCESS_ATTACH, (uint32_t)init_parameter);
                }
                else {
                    DllEntryProc64 DllEntry = (DllEntryProc64)(image_base + rva);
                    DllEntry(image_base, DLL_PROCESS_ATTACH, init_parameter);
                }
            }
            else {
                ExeEntryProc ExeEntry = (ExeEntryProc)(LPVOID)(image_base + rva);
                // exe不执行
            }
        }
        else {
            uint64_t entry_point = (uint64_t)image_base + image->GetEntryPoint();
            if (!Call(image_base, entry_point, { image_base, DLL_PROCESS_ATTACH , init_parameter }, nullptr, CallConvention::kStdCall, sync)) {
                return false;
            }
        }
        return true;
    }


    /*
    * Module
    */
    std::optional<std::vector<ModuleInfo>> GetModuleInfoList() const {
        /*
        * https://blog.csdn.net/wh445306/article/details/107867375
        */

        std::vector<ModuleInfo> moduleList;
        if (IsX86()) {
            HMODULE NtdllModule = GetModuleHandleW(L"ntdll.dll");
            pfnNtQueryInformationProcess NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(NtdllModule, "NtQueryInformationProcess");

            PROCESS_BASIC_INFORMATION32 pbi32 = { 0 };

            if (!NT_SUCCESS(NtQueryInformationProcess(Get(), ProcessBasicInformation, &pbi32, sizeof(pbi32), NULL))) {
                return {};
            }

            DWORD Ldr32 = 0;
            LIST_ENTRY32 ListEntry32 = { 0 };
            LDR_DATA_TABLE_ENTRY32 LDTE32 = { 0 };

            if (!ReadMemory((pbi32.PebBaseAddress + offsetof(PEB32, Ldr)), &Ldr32, sizeof(Ldr32))) {
                return {};
            }
            if (!ReadMemory((Ldr32 + offsetof(PEB_LDR_DATA32, InLoadOrderModuleList)), &ListEntry32, sizeof(ListEntry32))) {
                return {};
            }
            if (!ReadMemory((ListEntry32.Flink), &LDTE32, sizeof(LDTE32))) {
                return {};
            }

            while (true) {
                if (LDTE32.InLoadOrderLinks.Flink == ListEntry32.Flink) break;
                std::vector<wchar_t> full_name(LDTE32.FullDllName.Length + 1, 0);
                if (!ReadMemory(LDTE32.FullDllName.Buffer, (wchar_t*)full_name.data(), LDTE32.FullDllName.Length)) {
                    continue;
                }
                std::vector<wchar_t> base_name(LDTE32.BaseDllName.Length + 1, 0);
                if (!ReadMemory(LDTE32.BaseDllName.Buffer, (wchar_t*)base_name.data(), LDTE32.BaseDllName.Length)) {
                    continue;
                }
                ModuleInfo module(LDTE32, base_name.data(), full_name.data());
                moduleList.push_back(module);
                if (!ReadMemory(LDTE32.InLoadOrderLinks.Flink, &LDTE32, sizeof(LDTE32))) break;
            }
        }
        else {
            HMODULE NtdllModule = GetModuleHandleW(L"ntdll.dll");
            PROCESS_BASIC_INFORMATION64 pbi64 = { 0 };
            if (ms_wow64.Wow64Operation(Get())) {
                pfnNtWow64QueryInformationProcess64 NtWow64QueryInformationProcess64 = (pfnNtWow64QueryInformationProcess64)GetProcAddress(NtdllModule, "NtWow64QueryInformationProcess64");
                if (!NT_SUCCESS(NtWow64QueryInformationProcess64(Get(), ProcessBasicInformation, &pbi64, sizeof(pbi64), NULL))) {
                    return {};
                }
            }
            else {
                pfnNtQueryInformationProcess NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(NtdllModule, "NtQueryInformationProcess");
                if (!NT_SUCCESS(NtQueryInformationProcess(Get(), ProcessBasicInformation, &pbi64, sizeof(pbi64), NULL))) {
                    return {};
                }
            }

            DWORD64 Ldr64 = 0;
            LIST_ENTRY64 ListEntry64 = { 0 };
            LDR_DATA_TABLE_ENTRY64 LDTE64 = { 0 };
            wchar_t ProPath64[256];

            if (!ReadMemory((pbi64.PebBaseAddress + offsetof(PEB64, Ldr)), &Ldr64, sizeof(Ldr64))) {
                return {};
            }
            if (!ReadMemory((Ldr64 + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList)), &ListEntry64, sizeof(LIST_ENTRY64))) {
                return {};
            }
            if (!ReadMemory((ListEntry64.Flink), &LDTE64, sizeof(LDTE64))) {
                return {};
            }

            while (true) {
                if (LDTE64.InLoadOrderLinks.Flink == ListEntry64.Flink) break;
                std::vector<wchar_t> full_name(LDTE64.FullDllName.Length + 1, 0);
                if (!ReadMemory(LDTE64.FullDllName.Buffer, (wchar_t*)full_name.data(), LDTE64.FullDllName.Length)) {
                    if (!ReadMemory(LDTE64.InLoadOrderLinks.Flink, &LDTE64, sizeof(LDTE64))) break;
                    continue;
                }
                std::vector<wchar_t> base_name(LDTE64.BaseDllName.Length + 1, 0);
                if (!ReadMemory(LDTE64.BaseDllName.Buffer, (wchar_t*)base_name.data(), LDTE64.BaseDllName.Length)) {
                    if (!ReadMemory(LDTE64.InLoadOrderLinks.Flink, &LDTE64, sizeof(LDTE64))) break;
                    continue;
                }
                ModuleInfo module(LDTE64, base_name.data(), full_name.data());
                moduleList.push_back(module);
                if (!ReadMemory(LDTE64.InLoadOrderLinks.Flink, &LDTE64, sizeof(LDTE64))) break;
            }

        }
        return moduleList;
    }

    std::optional<ModuleInfo> GetModuleInfoByModuleName(std::wstring_view name) {
        std::wstring find_name = Geek::String::ToUppercase(std::wstring(name.data()));
        if (find_name == L"NTDLL") find_name += L".DLL";
        auto module_list_res = GetModuleInfoList();
        if (!module_list_res) return {};
        for (auto& it : module_list_res.value()) {
            auto base_name_up = Geek::String::ToUppercase(it.base_name);
            if (base_name_up == find_name) {
                return it;
            }
        }
        return {};
    }

    std::optional<ModuleInfo> GetModuleInfoByModuleBase(uint64_t base) {
        auto module_list = GetModuleInfoList();
        if (!module_list)return {};
        for (auto& it : module_list.value()) {
            if (it.base == base) {
                return it;
            }
        }
        return {};
    }

    static std::optional<std::vector<uint8_t>> GetResource(HMODULE hModule, DWORD ResourceID, LPCWSTR type) {
        bool success = false;
        std::vector<uint8_t> res;
        HRSRC hResID = NULL;
        HRSRC hRes = NULL;
        HANDLE hResFile = INVALID_HANDLE_VALUE;
        do {
            HRSRC hResID = FindResourceW(hModule, MAKEINTRESOURCEW(ResourceID), type);
            if (!hResID) {
                break;
            }

            HGLOBAL hRes = LoadResource(hModule, hResID);
            if (!hRes) {
                break;
            }

            LPVOID pRes = LockResource(hRes);
            if (pRes == NULL) {
                break;
            }

            unsigned long dwResSize = SizeofResource(hModule, hResID);
            res.resize(dwResSize);
            memcpy(&res[0], pRes, dwResSize);
            success = true;
        } while (false);

        if (hResFile != INVALID_HANDLE_VALUE) {
            
            hResFile = INVALID_HANDLE_VALUE;
        }
        if (hRes) {
            UnlockResource(hRes);
            FreeResource(hRes);
            hRes = NULL;
        }
        if (!success) {
            return {};
        }
        return res;
    }

    static bool SaveFileFromResource(HMODULE hModule, DWORD ResourceID, LPCWSTR type, LPCWSTR saveFilePath) {
        auto resource = GetResource(hModule, ResourceID, type);
        if (!resource) {
            return false;
        }
        return Geek::File::WriteFile(saveFilePath, resource->data(), resource->size());
    }

    
    /*
    * other
    */


public:
    //inline static const HANDLE kCurrentProcess = (HANDLE)-1;

private:
    UniqueHandle process_handle_;

private:
    //inline static Wow64 ms_wow64;

public:

    static bool CurIsX86() {
        Process process{ kCurrentProcess };
        return process.IsX86();
    }

    static DWORD GetProcessIdFromThread(Thread* thread) {
        return ::GetProcessIdOfThread(thread->Get());
    }

    static std::optional<std::vector<ProcessInfo>> GetProcessInfoList() {
        PROCESSENTRY32W pe32 = { 0 };
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        std::vector<ProcessInfo> processEntryList;

        UniqueHandle hProcessSnap{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL) };
        if (!Process32FirstW(hProcessSnap.Get(), &pe32)) {
            return {};
        }
        do {
            processEntryList.push_back(ProcessInfo(pe32));
        } while (Process32NextW(hProcessSnap.Get(), &pe32));
        return processEntryList;
    }

    static std::optional<std::map<DWORD, ProcessInfo>> GetProcessIdMap() {
        PROCESSENTRY32W pe32 = { 0 };
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        std::map<DWORD, ProcessInfo> process_map;

        UniqueHandle hProcessSnap{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL) };
        if (!Process32FirstW(hProcessSnap.Get(), &pe32)) {
            return {};
        }
        do {
            process_map.insert(std::make_pair(pe32.th32ProcessID, ProcessInfo(pe32)));
        } while (Process32NextW(hProcessSnap.Get(), &pe32));
        return process_map;
    }

    static std::optional<std::wstring> GetProcessNameByProcessId(DWORD pid, std::vector<ProcessInfo>* cache = nullptr) {
        std::vector<ProcessInfo>* process_list = cache;
        std::vector<ProcessInfo> copy;
        if (process_list == nullptr) {
            auto copy_res = GetProcessInfoList();
            if (!copy_res) return {};
            copy = std::move(*copy_res);
            process_list = &copy;
        }
        for (auto& process : *process_list) {
            if (pid == process.process_id) {
                return std::wstring(process.process_name);
            }
        }
        return {};
    }

    static std::optional<DWORD> GetProcessIdByProcessName(std::wstring_view processName, int count = 1) {
        auto process_entry_list = GetProcessInfoList();
        if (!process_entry_list) return {};

        std::wstring processName_copy = processName.data();
        int i = 0;
        for (auto& entry : process_entry_list.value()) {
            auto exeFile_str = Geek::String::ToUppercase(entry.process_name);
            processName_copy = Geek::String::ToUppercase(processName_copy);
            if (exeFile_str == processName_copy) {
                if (++i < count) {
                    continue;
                }
                return entry.process_id;
            }
        }
        return {};
    }

    static bool Terminate(std::wstring_view processName) {
        auto process = Open(processName);
        if (!process) return false;
        return process.value().Terminate(0);
    }
};

static inline Process ThisProcess{ kCurrentProcess };


} // namespace Geek

#endif // GEEK_PROCESS_PROCESS_HPP_
