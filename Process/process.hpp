#ifndef GEEK_PROCESS_PROCESS_H_
#define GEEK_PROCESS_PROCESS_H_

#include <string>
#include <vector>
#include <map>


#ifndef WINNT
#include <Windows.h>
#include <tlhelp32.h>
#else
#include <ntifs.h>
#endif


#include <Geek/Process/ntinc.h>
#include <Geek/Process/module.hpp>
#include <Geek/Process/memory_block.hpp>
#include <Geek/Handle/handle.hpp>
#include <Geek/PE/image.hpp>
#include <Geek/Thread/thread.hpp>
#include <Geek/wow64ext/wow64ext.hpp>
#include <Geek/String/string.hpp>

namespace Geek {

static Wow64 ms_wow64;
static const HANDLE kCurrentProcess = (HANDLE)-1;

class Process {
public:
  enum class Status {
    kOk,
    kProcessInvalid,
    kOther,
    kApiCallFailed,
  };

public:
  Process() {
    Open(UniqueHandle(kCurrentProcess));
  }

  void Open(UniqueHandle hProcess) {
    m_handle = std::move(hProcess);
  }

  bool Open(DWORD pid, DWORD desiredAccess = PROCESS_ALL_ACCESS) {
    auto hProcess = OpenProcess(desiredAccess, FALSE, pid);
    if (hProcess == NULL) {
      return false;
    }
    m_handle = UniqueHandle(hProcess);
    return true;
  }

  bool Open(const wchar_t* process_name, DWORD desiredAccess = PROCESS_ALL_ACCESS, int count = 1) {
    DWORD pid = GetProcessIdByProcessName(process_name, count);
    if (pid == 0) {
      return false;
    }
    return Open(pid, desiredAccess);
  }

  /*
  * CREATE_SUSPENDED:挂起目标进程
  */
  Status Create(const std::wstring& command, BOOL inheritHandles = FALSE, DWORD creationFlags = 0) {
    std::wstring command_ = command;
    STARTUPINFOW startupInfo{ sizeof(startupInfo) };
    PROCESS_INFORMATION processInformation{ 0 };
    if (!CreateProcessW(NULL, (LPWSTR)command_.c_str(), NULL, NULL, inheritHandles, creationFlags, NULL, NULL, &startupInfo, &processInformation)) {
      return Status::kApiCallFailed;
    }
    m_handle = UniqueHandle(processInformation.hProcess);
    CloseHandle(processInformation.hThread);
    return Status::kOk;
  }

  /*
  * L"explorer.exe"
  */
  bool CreateByToken(const std::wstring& tokenProcessName, const std::wstring& command, HANDLE* thread = NULL, BOOL inheritHandles = FALSE, DWORD creationFlags = 0, STARTUPINFOW* si = NULL, PROCESS_INFORMATION* pi = NULL) {
    HANDLE hToken_ = NULL;
    std::wstring tokenProcessName_ = tokenProcessName;
    DWORD pid = GetProcessIdByProcessName(tokenProcessName);
    if (pid == NULL) {
      return false;
    }
    UniqueHandle hProcess{ OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid) };
    OpenProcessToken(hProcess.Get(), TOKEN_ALL_ACCESS, &hToken_);
    if (hToken_ == NULL) {
      return false;
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
    std::wstring command_ = command;
    BOOL ret = CreateProcessAsUserW(hToken.Get(), NULL, (LPWSTR)command_.c_str(), NULL, NULL, inheritHandles, creationFlags | NORMAL_PRIORITY_CLASS, NULL, NULL, si, pi);
    if (!ret) {
      return false;
    }
    m_handle = UniqueHandle(pi->hProcess);
    if (!thread) {
      CloseHandle(pi->hThread);
    }
    else {
      *thread = pi->hThread;
    }
    return true;
  }

  bool Terminate(DWORD exitCode) {
    BOOL ret = ::TerminateProcess(Get(), exitCode);
    m_handle.Reset();
    return ret;
  }

  BOOL SetDebugPrivilege(BOOL IsEnable)
  {
    DWORD  LastError = 0;
    HANDLE TokenHandle = 0;

    if (!OpenProcessToken(Get(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle))
    {
      LastError = GetLastError();
      if (TokenHandle)
      {
        CloseHandle(TokenHandle);
      }
      return LastError;
    }
    TOKEN_PRIVILEGES TokenPrivileges;
    memset(&TokenPrivileges, 0, sizeof(TOKEN_PRIVILEGES));
    LUID v1;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &v1))
    {
      LastError = GetLastError();
      CloseHandle(TokenHandle);
      return LastError;
    }
    TokenPrivileges.PrivilegeCount = 1;
    TokenPrivileges.Privileges[0].Luid = v1;
    if (IsEnable)
    {
      TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    }
    else
    {
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
    return m_handle.Get();
  }

  DWORD GetId() const noexcept {
    return GetProcessId(Get());
  }

  bool IsX86() const noexcept {
    auto handle = Get();

    ::BOOL IsWow64;
    if (!::IsWow64Process(handle, &IsWow64)) {
      return true;
    }

    if (IsWow64) {
      return true;
    }

    ::SYSTEM_INFO SystemInfo = { 0 };
    ::GetNativeSystemInfo(&SystemInfo);    //���ϵͳ��Ϣ
    if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {    //�õ�ϵͳλ��64
      return false;
    }
    else if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {    // �õ�ϵͳλ��32
      return true;
    }
    return true;

  }

  bool IsCur() const {
    return Get() == kCurrentProcess;
  }
    
  /*
  * Memory
  */
  uint64_t AllocMemory(uint64_t addr, size_t len, DWORD type = MEM_RESERVE | MEM_COMMIT, DWORD protect = PAGE_READWRITE) {
    if (ms_wow64.Wow64Operation(Get())) {
      return (uint64_t)ms_wow64.VirtualAllocEx64(Get(), (DWORD64)addr, len, type, protect);
    }
    return (uint64_t)VirtualAllocEx(Get(), (LPVOID)addr, len, type, protect);
  }

  uint64_t AllocMemory(size_t len, DWORD type = MEM_RESERVE | MEM_COMMIT, DWORD protect = PAGE_READWRITE) {
    return AllocMemory(NULL, len, type, protect);
  }

  bool FreeMemory(uint64_t addr, size_t size = 0, DWORD type = MEM_RELEASE) {
    if (ms_wow64.Wow64Operation(Get())) {
      return ms_wow64.VirtualFreeEx64(Get(), (DWORD64)addr, size, type);
    }
    return VirtualFreeEx(Get(), (LPVOID)addr, size, type);
  }

  bool ReadMemory(uint64_t addr, void* buf, size_t len) const {
    if (this == nullptr) {
      memcpy(buf, (void*)addr, len);
      return true;
    }
    SIZE_T readByte;

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

  std::vector<char> ReadMemory(uint64_t addr, size_t len) const {
    std::vector<char> buf;
    buf.resize(len);
    if (!ReadMemory(addr, buf.data(), len)) {
      buf.clear();
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

  uint64_t WriteMemory(const void* buf, size_t len, DWORD protect = PAGE_READWRITE) {
    auto mem = AllocMemory(len, (DWORD)MEM_COMMIT, protect);
    if (!mem) {
      return 0;
    }
    WriteMemory(mem, buf, len);
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

  std::vector<MemoryBlock> EnumMemoryBlockList() const {
    std::vector<MemoryBlock> memoryBlockList;

    memoryBlockList.reserve(200);
    /*
    typedef struct _SYSTEM_INFO {
    union {
    DWORD dwOemId;
    struct {
    WORD wProcessorArchitecture;
    WORD wReserved;
    } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
    DWORD   dwPageSize;
    LPVOID  lpMinimumApplicationAddress;
    LPVOID  lpMaximumApplicationAddress;
    DWORD_PTR dwActiveProcessorMask;
    DWORD   dwNumberOfProcessors;
    DWORD   dwProcessorType;
    DWORD   dwAllocationGranularity;
    WORD    wProcessorLevel;
    WORD    wProcessorRevision;
    } SYSTEM_INFO, *LPSYSTEM_INFO;
    */

    uint64_t p = 0;
    MEMORY_BASIC_INFORMATION  memInfo = { 0 };
    MEMORY_BASIC_INFORMATION64  memInfo64 = { 0 };
    MemoryBlock temp;
    while (true) {
      uint64_t size;
      if (ms_wow64.Wow64Operation(Get())) {
        size = Geek::Wow64::VirtualQueryEx64(Get(), p, &memInfo64, sizeof(memInfo64));
        if (size != sizeof(memInfo64)) { break; }
        memoryBlockList.push_back(memInfo64);
        p += memInfo64.RegionSize;
      }
      else {
        size_t size = ::VirtualQueryEx(Get(), (PVOID)p, &memInfo, sizeof(memInfo));
        if (size != sizeof(memInfo)) { break; }
        if (IsX86()) {
          memoryBlockList.push_back(*(MEMORY_BASIC_INFORMATION32*)&memInfo);
        }
        else {
          memoryBlockList.push_back(*(MEMORY_BASIC_INFORMATION64*)&memInfo);
        }
        p += memInfo.RegionSize;
      }
      
    }
    return memoryBlockList;
  }

  bool ScanMemoryBlocks(bool(*callback)(uint64_t raw_addr, char* addr, size_t size, void* arg), void* arg, bool include_module = false) const {
    bool success = false;
    do {
      auto modulelist = EnumModuleListEx();
      auto vec = EnumMemoryBlockList();
      size_t sizeSum = 0;

      for (int i = 0; i < vec.size(); i++) {
        if (vec[i].protect & PAGE_NOACCESS || !vec[i].protect) {
          continue;
        }

        if (include_module == false) {
          bool isModule = false;
          for (int j = 0; j < modulelist.size(); j++) {
            if (vec[i].base >= modulelist[j].base && vec[i].base < modulelist[j].base + modulelist[j].base) {
              isModule = true;
              break;
            }
          }
          if (!(!isModule && vec[i].protect & PAGE_READWRITE && vec[i].state & MEM_COMMIT)) {
            continue;
          }
        }

        auto temp_buff = ReadMemory(vec[i].base, vec[i].size);
        if (temp_buff.empty()) {
          //printf("%d\n", GetLastError());
          continue;
        }
        
        if (callback(vec[i].base, temp_buff.data(), temp_buff.size(), arg)) {
          break;
        }
        sizeSum += vec[i].size;
      }
      success = true;
    } while (false);
    return success;
  }

    


    
  /*
  * Run
  */
  uint16_t LockAddress(uint64_t addr) {
    uint16_t instr;
    if (!ReadMemory(addr, &instr, 2)) {
      return 0;
    }
    unsigned char jmpSelf[] = { 0xeb, 0xfe };
    if (!WriteMemory(addr, jmpSelf, 2, true)) {
      return 0;
    }
    return instr;
  }

  bool UnlockAddress(uint64_t addr, uint16_t instr) {
    return WriteMemory(addr, &instr, 2, true);
  }

  /*
  * Thread
  */
  Thread CreateThread(PTHREAD_START_ROUTINE start_routine, PVOID64 parameter, DWORD dwCreationFlags = 0 /*CREATE_SUSPENDED*/) {
    DWORD thread_id = 0;
    HANDLE thread_handle = NULL;
    if (IsCur()) {
      thread_handle = ::CreateThread(NULL, 0, start_routine, parameter, dwCreationFlags, &thread_id);
    }
    else {
      thread_handle = ::CreateRemoteThread(Get(), NULL, 0, start_routine, parameter, dwCreationFlags, &thread_id);
    }
    if (thread_handle != NULL) {
      Thread thread;
      thread.Open(UniqueHandle(thread_handle));
      return thread;
    }
    return Thread();
  }

  uint16_t BlockThread(Thread* thread) {
    if (!thread->Suspend()) {
      return 0;
    }
    unsigned char jmpSelf[] = { 0xeb, 0xfe };
    bool isX86;
    auto contextBuf = GetThreadContext(thread, &isX86);
    uint64_t ip;
    if (isX86) {
      auto context = (_CONTEXT32*)contextBuf.data();
      ip = context->Eip;
    }
    else {
      auto context = (_CONTEXT64*)contextBuf.data();
      ip = context->Rip;
    }
    auto oldInstr = LockAddress(ip);
    thread->Resume();
    return oldInstr;
  }

  bool ResumeBlockedThread(Thread* thread, uint16_t instr) {
    if (!thread->Suspend()) {
      return false;
    }
    uint16_t oldInstr;
    bool isX86;
    auto contextBuf = GetThreadContext(thread, &isX86);
    uint64_t ip;
    if (isX86) {
      auto context = (_CONTEXT32*)contextBuf.data();
      ip = context->Eip;
    }
    else {
      auto context = (_CONTEXT64*)contextBuf.data();
      ip = context->Rip;
    }
    auto success = UnlockAddress(ip, instr);
    thread->Resume();
    return success;
  }

  bool IsTheOwningThread(Thread* thread) {
    return GetProcessIdOfThread(thread) == GetId();
  }

  std::vector<char> GetThreadContext(Thread* thread, bool* isX86 = nullptr, DWORD flags = CONTEXT_CONTROL | CONTEXT64_INTEGER) {
    std::vector<char> context;
    bool success;
    if (!IsTheOwningThread(thread)) {
      return context;
    }
    if (ms_wow64.Wow64Operation(Get())) {
      context.resize(sizeof(_CONTEXT64));
      ((_CONTEXT64*)context.data())->ContextFlags = flags;
      success = ms_wow64.GetThreadContext64(thread->Get(), (_CONTEXT64*)context.data());
      if (isX86) *isX86 = false;
    }
    else {
      if (IsX86() && !CurIsX86()) {
        if (isX86) *isX86 = true;
        context.resize(sizeof(WOW64_CONTEXT));
        ((WOW64_CONTEXT*)context.data())->ContextFlags = flags;
        success = ::Wow64GetThreadContext(thread->Get(), (PWOW64_CONTEXT)context.data());
      }
      else {
        if (isX86) *isX86 = false;
        context.resize(sizeof(CONTEXT));
        ((CONTEXT*)context.data())->ContextFlags = flags;
        success = ::GetThreadContext(thread->Get(), (LPCONTEXT)context.data());
      }
    }
    if (!success) {
      context.clear();
    }
    return context;
  }

  bool WaitExit(DWORD dwMilliseconds = INFINITE) {
    if (IsCur()) {
      return false;
    }
    return WaitForSingleObject(Get(), dwMilliseconds) == WAIT_OBJECT_0;
  }

  DWORD GetExitCode() {
    DWORD code;
    GetExitCodeProcess(Get(), &code);
    return code;
  }

  /*
  * Image
  */
  static uint64_t LoadLibraryDefault(Process* process, const char* lib_name) {
    if (process->IsCur()) {
      return (uint64_t)LoadLibraryA(lib_name);
    }
    Module module;
    if (process->FindModlueByModuleName(Geek::String::AnsiToUtf16le(lib_name), &module)) {
      return module.base;
    }

    uint64_t addr = NULL;
    auto len = strlen(lib_name) + 1;
    auto lib_name_buf = process->AllocMemory(len);

    do {
      if (!lib_name_buf) {
        break;
      }
      if (!process->WriteMemory(lib_name_buf, lib_name, len)) {
        break;
      }
      auto thread = process->CreateThread((PTHREAD_START_ROUTINE)LoadLibraryA, (PVOID64)lib_name_buf);
      if (thread.IsCur()) {
        break;
      }
      thread.WaitExit();
      addr = thread.GetExitCode();
    } while (false);
    if (lib_name_buf) {
      process->FreeMemory(lib_name_buf);
    }
    return addr;
  }

  static void FreeLibraryDefault(Process* process, uint64_t module_base) {
    if (process->IsCur()) {
      FreeLibrary((HMODULE)module_base);
      return;
    }
    do {
      auto thread = process->CreateThread((PTHREAD_START_ROUTINE)FreeLibrary, (PVOID64)module_base);
      if (thread.IsCur()) {
        break;
      }
      thread.WaitExit(INFINITE);
    } while (false);
  }

  /* ������ڴ�ע�뻹��Ҫ���image�е���LoadLibraryDefault�����ص�ģ���ַ���ǵ�ǰ����ģ���ַ������ */
  uint64_t LoadLibraryFromImage(Image* image, Image::LoadLibraryFunc load_library_func, bool call_dll_entry = true, uint64_t init_parameter = 0, bool skip_not_loaded = false, bool zero_pe_header = true) {
    if (IsX86() != image->IsPE32()) {
      return 0;
    }
    auto image_base = AllocMemory(NULL, image->GetImageSize(), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    bool success = false;
    do {
      if (!image_base) {
        break;
      }
      if (!image->RepairRepositionTable((uint64_t)image_base)) {
        break;
      }
      if (!image->RepairImportAddressTable(load_library_func, this, skip_not_loaded)) {
        break;
      }
      auto image_buf = image->SaveToImageBuf((uint64_t)image_base, zero_pe_header);
      if (IsCur()) {
        if (!WriteMemory(image_base, image_buf.data(), image_buf.size())) {
          break;
        }
        image->ExecuteTls((uint64_t)image_base);
        if (call_dll_entry) {
          image->CallEntryPoint((uint64_t)image_base, init_parameter);
        }
      }
      else {
        uint64_t entry_point = (uint64_t)image_base + image->GetEntryPoint();
        if (image->IsPE32()) {
          int offset = 0;
          image_buf[offset++] = 0x68;    // push 0
          *(uint32_t*)&image_buf[offset] = (uint32_t)init_parameter;
          offset += 4;

          image_buf[offset++] = 0x68;    // push DLL_PROCESS_ATTACH
          *(uint32_t*)&image_buf[offset] = DLL_PROCESS_ATTACH;
          offset += 4;

          image_buf[offset++] = 0x68;    // push image_base
          *(uint32_t*)&image_buf[offset] = (uint32_t)image_base;
          offset += 4;

          image_buf[offset++] = 0xb8;    // mov eax, entry_point
          *(uint32_t*)&image_buf[offset] = (uint32_t)entry_point;
          offset += 4;

          image_buf[offset++] = 0xff;    // call eax
          image_buf[offset++] = 0xd0;

          image_buf[offset++] = 0xc2;    // ret 4
          *(uint16_t*)&image_buf[offset] = 4;
          offset += 2;
        }
        else {
          /*
          * 64λ�£�ջ��Ҫ16�ֽڶ��룬������һЩָ���쳣(��movaps)
          * ��Ϊ����һ��callѹ��ķ��ص�ַ������-28
          */
          int offset = 0;
          image_buf[offset++] = 0x48;    // sub rsp, 28
          image_buf[offset++] = 0x83;
          image_buf[offset++] = 0xec;
          image_buf[offset++] = 0x28;

          // ���ݲ���
          image_buf[offset++] = 0x48;    // mov rcx, image_base
          image_buf[offset++] = 0xb9;
          *(uint64_t*)&image_buf[offset] = (uint64_t)image_base;
          offset += 8;

          image_buf[offset++] = 0x48;    // mov rdx, DLL_PROCESS_ATTACH
          image_buf[offset++] = 0xc7;
          image_buf[offset++] = 0xc2;
          *(uint32_t*)&image_buf[offset] = 1;
          offset += 4;

          image_buf[offset++] = 0x49;    // mov r8, init_parameter
          image_buf[offset++] = 0xb8;
          *(uint64_t*)&image_buf[offset] = init_parameter;
          offset += 8;


          image_buf[offset++] = 0x48;    // mov rax, entry_point
          image_buf[offset++] = 0xb8;
          *(uint64_t*)&image_buf[offset] = entry_point;
          offset += 8;

          image_buf[offset++] = 0xff;    // call rax
          image_buf[offset++] = 0xd0;

          // ����ջ�ռ�
          image_buf[offset++] = 0x48;    // add rsp, 28
          image_buf[offset++] = 0x83;
          image_buf[offset++] = 0xc4;
          image_buf[offset++] = 0x28;

          image_buf[offset++] = 0xc3;    // ret
        }
        if (!WriteMemory(image_base, image_buf.data(), image_buf.size())) {
          break;
        }
        CreateThread((PTHREAD_START_ROUTINE)image_base, NULL);
      }
      success = true;
    } while (false);
    if (success == false && image_base) {
      FreeMemory(image_base);
      image_base = 0;
    }
    return image_base;
  }

  
  /*
  * Module
  */
  std::vector<Module> EnumModuleListEx() const {
    /*
    * https://blog.csdn.net/wh445306/article/details/107867375
    */

    std::vector<Module> moduleList;
    if (IsX86()) {
      do {
        HMODULE NtdllModule = GetModuleHandleW(L"ntdll.dll");
        pfnNtQueryInformationProcess NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(NtdllModule, "NtQueryInformationProcess");

        PROCESS_BASIC_INFORMATION32 pbi32 = { 0 };

        if (!NT_SUCCESS(NtQueryInformationProcess(Get(), ProcessBasicInformation, &pbi32, sizeof(pbi32), NULL))) {
          break;
        }

        DWORD Ldr32 = 0;
        LIST_ENTRY32 ListEntry32 = { 0 };
        LDR_DATA_TABLE_ENTRY32 LDTE32 = { 0 };

        if (!ReadMemory((pbi32.PebBaseAddress + offsetof(PEB32, Ldr)), &Ldr32, sizeof(Ldr32))) {
          break;
        }
        if (!ReadMemory((Ldr32 + offsetof(PEB_LDR_DATA32, InLoadOrderModuleList)), &ListEntry32, sizeof(ListEntry32))) {
          break;
        }
        if (!ReadMemory((ListEntry32.Flink), &LDTE32, sizeof(LDTE32))) {
          break;
        }

        while (true) {
          if (LDTE32.InLoadOrderLinks.Flink == ListEntry32.Flink) break;
          std::vector<wchar_t>  full_name(LDTE32.FullDllName.Length + 1, 0);
          if (!ReadMemory(LDTE32.FullDllName.Buffer, (wchar_t*)full_name.data(), LDTE32.FullDllName.Length)) {
            continue;
          }
          std::vector<wchar_t>  base_name(LDTE32.BaseDllName.Length + 1, 0);
          if (!ReadMemory(LDTE32.BaseDllName.Buffer, (wchar_t*)base_name.data(), LDTE32.BaseDllName.Length)) {
            continue;
          }
          Module module(LDTE32, base_name.data(), full_name.data());
          moduleList.push_back(module);
          if (!ReadMemory(LDTE32.InLoadOrderLinks.Flink, &LDTE32, sizeof(LDTE32))) break;
        }
      } while (false);
    }
    else {
      do {
        HMODULE NtdllModule = GetModuleHandleW(L"ntdll.dll");
        PROCESS_BASIC_INFORMATION64 pbi64 = { 0 };
        if (ms_wow64.Wow64Operation(Get())) {
          pfnNtWow64QueryInformationProcess64 NtWow64QueryInformationProcess64 = (pfnNtWow64QueryInformationProcess64)GetProcAddress(NtdllModule, "NtWow64QueryInformationProcess64");
          if (!NT_SUCCESS(NtWow64QueryInformationProcess64(Get(), ProcessBasicInformation, &pbi64, sizeof(pbi64), NULL))) {
            break;
          }
        }
        else {
          pfnNtQueryInformationProcess NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(NtdllModule, "NtQueryInformationProcess");
          if (!NT_SUCCESS(NtQueryInformationProcess(Get(), ProcessBasicInformation, &pbi64, sizeof(pbi64), NULL))) {
            break;
          }
        }

        DWORD64 Ldr64 = 0;
        LIST_ENTRY64 ListEntry64 = { 0 };
        LDR_DATA_TABLE_ENTRY64 LDTE64 = { 0 };
        wchar_t ProPath64[256];

        if (!ReadMemory((pbi64.PebBaseAddress + offsetof(PEB64, Ldr)), &Ldr64, sizeof(Ldr64))) {
          break;
        }
        if (!ReadMemory((Ldr64 + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList)), &ListEntry64, sizeof(LIST_ENTRY64))) {
          break;
        }
        if (!ReadMemory((ListEntry64.Flink), &LDTE64, sizeof(LDTE64))) {
          break;
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
          Module module(LDTE64, base_name.data(), full_name.data());
          moduleList.push_back(module);
          if (!ReadMemory(LDTE64.InLoadOrderLinks.Flink, &LDTE64, sizeof(LDTE64))) break;
        }

      } while (false);
    }
    return moduleList;
  }

  bool FindModlueByModuleName(const std::wstring& name, Module* module = nullptr) {
    std::wstring find_name = Geek::String::ToUppercase(name);
    for (auto& it : EnumModuleListEx()) {
      auto base_name_up = Geek::String::ToUppercase(it.base_name);
      if (base_name_up == find_name) {
        if (module) *module = it;
        return true;
      }
    }
    return false;
  }

  static bool SaveFileFromResource(HMODULE hModule, DWORD ResourceID, LPCWSTR type, LPCWSTR saveFilePath) {
    bool success = false;
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
      if (pRes == NULL)
      {
        break;
      }

      unsigned long dwResSize = SizeofResource(hModule, hResID);

      hResFile = CreateFileW(saveFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
      if (INVALID_HANDLE_VALUE == hResFile)
      {
        DWORD errorCode = GetLastError();
        if (errorCode == 32) {
          success = true;
          break;
        }
        break;
      }
      DWORD dwWrited = 0;
      if (FALSE == WriteFile(hResFile, pRes, dwResSize, &dwWrited, NULL))
      {
        break;
      }
      success = true;
    } while (false);

    if (hResFile != INVALID_HANDLE_VALUE) {
      CloseHandle(hResFile);
      hResFile = INVALID_HANDLE_VALUE;
    }
    if (hRes) {
      UnlockResource(hRes);
      FreeResource(hRes);
      hRes = NULL;
    }
    return success;

  }

  std::vector<MODULEENTRY32W> EnumModuleList() const {
    std::vector<MODULEENTRY32W> moduleList;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetId());
    if (hSnapshot == INVALID_HANDLE_VALUE) {
      return moduleList;
    }

    MODULEENTRY32 mi = { 0 };
    mi.dwSize = sizeof(MODULEENTRY32); //��һ��ʹ�ñ����ʼ����Ա
    BOOL bRet = Module32First(hSnapshot, &mi);
    do {
      if (bRet == false) {
        break;
      }
      do {
        moduleList.push_back(mi);
        bRet = Module32Next(hSnapshot, &mi);
      } while (bRet);
    } while (false);

    CloseHandle(hSnapshot);
    return moduleList;
  }

  
  /*
  * other
  */


public:
  //inline static const HANDLE kCurrentProcess = (HANDLE)-1;

private:
  UniqueHandle m_handle;

private:
  //inline static Wow64 ms_wow64;

public:

  static bool CurIsX86() {
    Process process;
    return process.IsX86();
  }

  static DWORD GetProcessIdOfThread(Thread* thread) {
    return ::GetProcessIdOfThread(thread->Get());
  }

  static std::vector<PROCESSENTRY32W> GetProcessList() {
    PROCESSENTRY32W pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    std::vector<PROCESSENTRY32W> processEntryList;

    UniqueHandle hProcessSnap{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL) };
    if (!Process32FirstW(hProcessSnap.Get(), &pe32)) {
      return processEntryList;
    }
    do {
      processEntryList.push_back(pe32);
    } while (Process32NextW(hProcessSnap.Get(), &pe32));
    return processEntryList;
  }

  static std::map<DWORD, PROCESSENTRY32W> GetProcessIdMap() {
    PROCESSENTRY32W pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    std::map<DWORD, PROCESSENTRY32W> process_map;

    UniqueHandle hProcessSnap{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL) };
    if (!Process32FirstW(hProcessSnap.Get(), &pe32)) {
      return process_map;
    }
    do {
      process_map.insert(std::make_pair(pe32.th32ProcessID, pe32));
    } while (Process32NextW(hProcessSnap.Get(), &pe32));
    return process_map;
  }

  static std::wstring GetProcessNameByProcessId(DWORD pid, std::vector<PROCESSENTRY32W>* cache = nullptr) {
    std::vector<PROCESSENTRY32W>* process_list = cache;
    std::vector<PROCESSENTRY32W> copy;
    if (process_list == nullptr) {
      copy = GetProcessList();
      process_list = &copy;
    }
    else if(process_list->empty()) {
      *process_list = GetProcessList();
    }
    for (auto& process : *process_list) {
      if (pid == process.th32ProcessID) {
        return std::wstring(process.szExeFile);
      }
    }
    return L"";
  }

  static DWORD GetProcessIdByProcessName(const std::wstring& processName, int count = 1) {
    auto processEntryList = GetProcessList();
    std::wstring processName_ = processName;
    if (processEntryList.empty()) {
      return NULL;
    }
    int i = 0;
    for (auto& entry : processEntryList) {
      auto exeFile_str = Geek::String::ToUppercase(std::wstring(entry.szExeFile));
      processName_ = Geek::String::ToUppercase(processName_);
      if (exeFile_str == processName_) {
        if (++i < count) {
          continue;
        }
        return entry.th32ProcessID;
      }
    }
    return NULL;
  }

  static bool Terminate(const std::wstring& processName) {
    auto pid = GetProcessIdByProcessName(processName);
    if (pid == 0) {
      return false;
    }
    Process process;
    if (!process.Open(pid)) {
      return false;
    }
    process.Terminate(0);
    return true;
  }
};

} // namespace Geek

#endif // GEEK_PROCESS_PROCESS_H_
