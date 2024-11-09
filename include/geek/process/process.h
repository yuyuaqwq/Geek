#pragma once
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <functional>

#ifndef WINNT
#include <Windows.h>
#include <tlhelp32.h>
//#include <Winternl.h>
#else
#include <ntifs.h>
#endif

#include <geek/process/thread.h>
#include <geek/process/module_list.h>
#include <geek/pe/image.h>
#include <geek/utils/handle.h>
#include <geek/wow64ext/wow64ext.h>
#include <geek/process/process_list.h>
#include <geek/process/address.h>

#include "ntinc.h"

namespace geek {
static inline Wow64 ms_wow64;

class Process;

class NewlyCreatedProcessInfo {
public:
	NewlyCreatedProcessInfo(const PROCESS_INFORMATION& info);

	Process NewlyProcess() const;
	Thread NewlyThread() const;

private:
	PROCESS_INFORMATION info_;
};

struct CallContextX86 {
	uint32_t eax = 0;
	uint32_t ecx = 0;
	uint32_t edx = 0;
	uint32_t ebx = 0;
	uint32_t esi = 0;
	uint32_t edi = 0;
	int32_t balanced_esp = 0;
	std::initializer_list<uint32_t> stack; // 目前调用完，不会将栈拷贝回来，如果是创建线程调用，则最多只能传递32个参数
};

struct CallContextX64 {
	uint64_t rax = 0;
	uint64_t rcx = 0;
	uint64_t rdx = 0;
	uint64_t rbx = 0;
	uint64_t rbp = 0;
	uint64_t rsi = 0;
	uint64_t rdi = 0;
	uint64_t r8 = 0;
	uint64_t r9 = 0;
	uint64_t r10 = 0;
	uint64_t r11 = 0;
	uint64_t r12 = 0;
	uint64_t r13 = 0;
	uint64_t r14 = 0;
	uint64_t r15 = 0;
	std::initializer_list<uint64_t> stack;
};

class Process {
public:
	explicit Process(UniqueHandle process_handle) noexcept;

	static std::optional<Process> Open(DWORD pid, DWORD desiredAccess = PROCESS_ALL_ACCESS);
	static std::optional<Process> Open(std::wstring_view process_name, DWORD desiredAccess = PROCESS_ALL_ACCESS);

	/*
	* CREATE_SUSPENDED:挂起目标进程
	*/
	static std::optional<NewlyCreatedProcessInfo> Create(std::wstring_view command, BOOL inheritHandles = FALSE,
	                                                     DWORD creationFlags = 0);

	/*
	* L"explorer.exe"
	*/
	static std::optional<NewlyCreatedProcessInfo> CreateByToken(std::wstring_view tokenProcessName,
	                                                            std::wstring_view command, BOOL inheritHandles = FALSE,
	                                                            DWORD creationFlags = 0, STARTUPINFOW* si = NULL,
	                                                            PROCESS_INFORMATION* pi = NULL);

	std::vector<uint64_t> SearchSig(std::string_view hex_string, uint64_t start_address, size_t size) const;

	bool Terminate(uint32_t exitCode);
	bool SetDebugPrivilege(bool IsEnable) const;

	HANDLE Handle() const noexcept;
	DWORD ProcId() const noexcept;
	bool IsX32() const noexcept;
	bool IsCurrent() const;

	std::optional<uint64_t> AllocMemory(uint64_t addr, size_t len, DWORD type = MEM_RESERVE | MEM_COMMIT,
	                                    DWORD protect = PAGE_READWRITE) const;
	std::optional<uint64_t> AllocMemory(size_t len, DWORD type = MEM_RESERVE | MEM_COMMIT,
	                                    DWORD protect = PAGE_READWRITE) const;
	bool FreeMemory(uint64_t addr, size_t size = 0, DWORD type = MEM_RELEASE) const;

	bool ReadMemory(uint64_t addr, void* buf, size_t len) const;
	std::optional<std::vector<uint8_t>> ReadMemory(uint64_t addr, size_t len) const;
	template <class T>
	std::optional<T> ReadMemoryToValue(uint64_t addr) const;

	bool WriteMemory(uint64_t addr, const void* buf, size_t len, bool force = false) const;
	std::optional<uint64_t> WriteMemoryWithAlloc(const void* buf, size_t len, DWORD protect = PAGE_READWRITE) const;
	bool SetMemoryProtect(uint64_t addr, size_t len, DWORD newProtect, DWORD* oldProtect) const;
	// std::optional<MemoryInfo> GetMemoryInfo(uint64_t addr) const;
	// std::optional<std::vector<MemoryInfo>> GetMemoryInfoList() const;
	// bool ScanMemoryInfoList(const std::function<bool(uint64_t raw_addr, uint8_t* addr, size_t size)>& callback, bool include_module = false) const;

	Address At(uint64_t addr) const;

	std::wstring DebugName() const;
	std::optional<std::wstring> BaseName() const;
	std::optional<std::wstring> GetCommandLineStr() const;

	std::optional<uint16_t> LockAddress(uint64_t addr) const;
	bool UnlockAddress(uint64_t addr, uint16_t instr) const;

	std::optional<Thread> CreateThread(uint64_t start_routine, uint64_t parameter,
	                                   DWORD dwCreationFlags = 0 /*CREATE_SUSPENDED*/) const;
	std::optional<uint16_t> BlockThread(Thread* thread) const;
	bool ResumeBlockedThread(Thread* thread, uint16_t instr) const;
	bool IsTheOwningThread(Thread* thread) const;
	bool GetThreadContext(Thread* thread, _CONTEXT32& context,
	                      DWORD flags = CONTEXT64_CONTROL | CONTEXT64_INTEGER) const;
	bool GetThreadContext(Thread* thread, _CONTEXT64& context,
	                      DWORD flags = CONTEXT64_CONTROL | CONTEXT64_INTEGER) const;
	bool SetThreadContext(Thread* thread, _CONTEXT32& context,
	                      DWORD flags = CONTEXT64_CONTROL | CONTEXT64_INTEGER) const;
	bool SetThreadContext(Thread* thread, _CONTEXT64& context,
	                      DWORD flags = CONTEXT64_CONTROL | CONTEXT64_INTEGER) const;
	bool WaitExit(DWORD dwMilliseconds = INFINITE) const;
	std::optional<DWORD> GetExitCode() const;

	//TODO LoadLibraryFromImage
	// std::optional<uint64_t> LoadLibraryFromImage(
	//     Image* image,
	//     bool exec_tls_callback = true,
	//     bool call_dll_entry = true,
	//     uint64_t init_parameter = 0,
	//     bool skip_not_loaded = false,
	//     bool zero_pe_header = true,
	//     bool entry_call_sync = true);

	std::optional<Image> LoadImageFromImageBase(uint64_t base) const;
	bool FreeLibraryFromImage(Image* image, bool call_dll_entry = true) const;

	std::optional<uint64_t> LoadLibraryW(std::wstring_view lib_name, bool sync = true);
	bool FreeLibrary(uint64_t module_base) const;
	//TODO GetExportProcAddress
	// std::optional<uint64_t> GetExportProcAddress(Image* image, const char* func_name);

	// 此处的Call开销较大，非跨进程/少量调用的场景，请使用传递CallContext的Call
	// 注：如果调用的是X86，par_list传递uint64_t会被截断为uint32_t
	enum class CallConvention {
		kStdCall,
	};

	bool Call(
		uint64_t exec_page,
		uint64_t call_addr,
		const std::vector<uint64_t>& par_list = {},
		uint64_t* ret_value = nullptr,
		CallConvention call_convention = CallConvention::kStdCall,
		bool sync = true,
		bool init_exec_page = true);
	bool Call(
		uint64_t call_addr,
		const std::vector<uint64_t>& par_list = {},
		uint64_t* ret_value = nullptr,
		CallConvention call_convention = CallConvention::kStdCall);

	bool CallGenerateCodeX86(uint64_t exec_page, bool sync) const;
	bool Call(uint64_t exec_page, uint64_t call_addr, CallContextX86* context, bool sync = true,
	          bool init_exec_page = true) const;
	bool Call(uint64_t call_addr, CallContextX86* context, bool sync = true) const;

	bool CallGenerateCodeX64(uint64_t exec_page, bool sync) const;
	bool Call(uint64_t exec_page, uint64_t call_addr, CallContextX64* context, bool sync = true,
	          bool init_exec_page = true) const;
	bool Call(uint64_t call_addr, CallContextX64* context, bool sync = true) const;

	//TODO RepairImportAddressTable
	// bool RepairImportAddressTable(Image* image, bool skip_not_loaded = false);

	//TODO ExecuteTls
	// PIMAGE_TLS_CALLBACK
	// bool ExecuteTls(Image* image, uint64_t image_base);

	const ModuleList& Modules() const;

	bool CallEntryPoint(Image* image, uint64_t image_base, uint64_t init_parameter = 0, bool sync = true);

	std::optional<PROCESS_BASIC_INFORMATION32> Pbi32() const;
	std::optional<PROCESS_BASIC_INFORMATION64> Pbi64() const;
	std::optional<PEB32> Peb32() const;
	std::optional<PEB64> Peb64() const;

	static ProcessList& CachedProcessList();
	static std::optional<std::vector<uint8_t>> GetResource(HMODULE hModule, DWORD ResourceID, LPCWSTR type);
	static bool SaveFileFromResource(HMODULE hModule, DWORD ResourceID, LPCWSTR type, LPCWSTR saveFilePath);
	static DWORD GetProcessIdFromThread(Thread* thread);
	static bool Terminate(std::wstring_view processName);

private:
	UniqueHandle process_handle_;
	mutable std::optional<ModuleList> modules_;
};

template <class T>
std::optional<T> Process::ReadMemoryToValue(uint64_t addr) const {
	T tmp;
	if (!ReadMemory(addr, &tmp, sizeof(T)))
		return std::nullopt;
	return tmp;
}

Process& ThisProc();
} // namespace geek
