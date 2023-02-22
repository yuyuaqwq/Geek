#ifndef GEEK_PROCESS_PROCESS_H_
#define GEEK_PROCESS_PROCESS_H_

#include <string>
#include <vector>

#include <Windows.h>
#include <tlhelp32.h>

#include <Geek/Process/ntinc.h>
#include <Geek/Handle/handle.hpp>
#include <Geek/wow64ext/wow64ext.hpp>

namespace Geek {

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

		/*
		* CREATE_SUSPENDED:创建挂起进程
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
		bool CreateByToken(const std::wstring& tokenProcessName, const std::wstring& command, HANDLE* thread, BOOL inheritHandles = FALSE, DWORD creationFlags = 0, STARTUPINFOW* si = NULL, PROCESS_INFORMATION* pi = NULL) {
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
			LUID v1;//权限类型，本地独有标识
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
			::GetNativeSystemInfo(&SystemInfo);		//获得系统信息
			if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {		//得到系统位数64
				return false;
			}
			else if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {		// 得到系统位数32
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
		PVOID64 AllocMemory(PVOID64 addr, size_t len, DWORD type = MEM_COMMIT, DWORD protect = PAGE_READWRITE) {
			if (ms_wow64.Wow64Operation(Get())) {
				return (PVOID64)ms_wow64.VirtualAllocEx64(Get(), (DWORD64)addr, len, type, protect);
			}
			return VirtualAllocEx(Get(), addr, len, type, protect);
		}

		PVOID64 AllocMemory(size_t len, DWORD type = MEM_COMMIT, DWORD protect = PAGE_READWRITE) {
			return AllocMemory(NULL, len, type, protect);
		}

		bool FreeMemory(PVOID64 addr, size_t size = 0, DWORD type = MEM_RELEASE) {
			if (ms_wow64.Wow64Operation(Get())) {
				return ms_wow64.VirtualFreeEx64(Get(), (DWORD64)addr, size, type);
			}
			return VirtualFreeEx(Get(), addr, size, type);
		}

		bool ReadMemory(PVOID64 addr, void* buf, size_t len) {
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

		std::vector<char> ReadMemory(PVOID64 addr, size_t len) {
			std::vector<char> buf;
			buf.resize(len);
			if (!ReadMemory(addr, buf.data(), len)) {
				buf.clear();
			}
			return buf;
		}

		bool WriteMemory(PVOID64 addr, const void* buf, size_t len, bool force = false) {
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
					memcpy(addr, buf, len);
				}
				else if (!::WriteProcessMemory(Get(), addr, buf, len, &readByte)) {
					success = false;
				}
			}
			if (force) {
				SetMemoryProtect(addr, len, oldProtect, &oldProtect);
			}
			return true;
		}

		PVOID64 WriteMemory(const void* buf, size_t len, DWORD protect = PAGE_READWRITE) {
			auto mem = AllocMemory(len, MEM_COMMIT, protect);
			if (!mem) {
				return nullptr;
			}
			WriteMemory(mem, buf, len);
			return mem;
		}

		bool SetMemoryProtect(PVOID64 addr, size_t len, DWORD newProtect, DWORD* oldProtect) {
			bool success = false;
			if (ms_wow64.Wow64Operation(Get())) {
				success = ms_wow64.VirtualProtectEx64(Get(), (DWORD64)addr, len, newProtect, oldProtect);
			}
			else {
				success = ::VirtualProtectEx(Get(), addr, len, newProtect, oldProtect);
			}
			return success;
		}


		std::vector<MEMORY_BASIC_INFORMATION> EnumAllMemoryBlocks() const {
			std::vector<MEMORY_BASIC_INFORMATION> memoryBlockList;

			// 初始化 vector 容量
			memoryBlockList.reserve(200);

			// 获取 PageSize 和地址粒度
			SYSTEM_INFO sysInfo = { 0 };
			GetSystemInfo(&sysInfo);
			/*
			typedef struct _SYSTEM_INFO {
			union {
			DWORD dwOemId;							// 兼容性保留
			struct {
			WORD wProcessorArchitecture;			// 操作系统处理器体系结构
			WORD wReserved;						// 保留
			} DUMMYSTRUCTNAME;
			} DUMMYUNIONNAME;
			DWORD     dwPageSize;						// 页面大小和页面保护和承诺的粒度
			LPVOID    lpMinimumApplicationAddress;	// 指向应用程序和dll可访问的最低内存地址的指针
			LPVOID    lpMaximumApplicationAddress;	// 指向应用程序和dll可访问的最高内存地址的指针
			DWORD_PTR dwActiveProcessorMask;			// 处理器掩码
			DWORD     dwNumberOfProcessors;			// 当前组中逻辑处理器的数量
			DWORD     dwProcessorType;				// 处理器类型，兼容性保留
			DWORD     dwAllocationGranularity;		// 虚拟内存的起始地址的粒度
			WORD      wProcessorLevel;				// 处理器级别
			WORD      wProcessorRevision;				// 处理器修订
			} SYSTEM_INFO, *LPSYSTEM_INFO;
			*/

			//遍历内存
			const char* p = (const char*)sysInfo.lpMinimumApplicationAddress;
			MEMORY_BASIC_INFORMATION  memInfo = { 0 };
			while (p < sysInfo.lpMaximumApplicationAddress) {
				// 获取进程虚拟内存块缓冲区字节数
				size_t size = VirtualQueryEx(Get(), p, &memInfo, sizeof(MEMORY_BASIC_INFORMATION32));
				if (size != sizeof(MEMORY_BASIC_INFORMATION32)) { break; }

				// 将内存块信息追加到 vector 数组尾部
				memoryBlockList.push_back(memInfo);

				// 移动指针
				p += memInfo.RegionSize;
			}
			return memoryBlockList;
		}

		std::vector<MODULEENTRY32W> EnumAllProcessModules() const {
			std::vector<MODULEENTRY32W> moduleList;
			HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetId());
			if (hSnapshot == INVALID_HANDLE_VALUE) {
				return moduleList;
			}

			MODULEENTRY32 mi = { 0 };
			mi.dwSize = sizeof(MODULEENTRY32); //第一次使用必须初始化成员
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

		bool MemoryDump(bool(*callback)(char*, size_t, void*), void* arg) const {
			HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			PROCESSENTRY32 process = { sizeof(PROCESSENTRY32) };
			bool success = false;

			std::vector<char> buf;

			do {
				std::vector<MODULEENTRY32> modulelist = EnumAllProcessModules();

				std::vector<MEMORY_BASIC_INFORMATION> vec = EnumAllMemoryBlocks();

				// 遍历该进程的内存块
				size_t sizeSum = 0;

				//if (compress) {
				//	_outFilePath += L".temp";
				//}
				// CreateDirectoryW((path + L"\\temp").c_str(), NULL);
				for (int i = 0; i < vec.size(); i++) {
					bool isModule = false;
					for (int j = 0; j < modulelist.size(); j++) {
						if (vec[i].BaseAddress >= modulelist[j].modBaseAddr && vec[i].BaseAddress < modulelist[j].modBaseAddr + modulelist[j].modBaseSize) {
							isModule = true;
							break;
						}
					}
					if (!(!isModule && vec[i].AllocationProtect & PAGE_READWRITE && vec[i].State & MEM_COMMIT)) {
						continue;
					}

					std::vector<char> tempBuff(vec[i].RegionSize);

					DWORD readCount = 0;
					if (!ReadProcessMemory(Get(), vec[i].BaseAddress, tempBuff.data(), vec[i].RegionSize, &readCount)) {
						printf("%d\n", GetLastError());
						continue;
					}
					printf("%d/%d\n", i, vec.size());
					if (callback(tempBuff.data(), tempBuff.size(), arg)) {
						break;
					}
					sizeSum += vec[i].RegionSize;
				}

				success = true;
			} while (false);

			return success;
		}

		


		
		/*
		* Run
		*/
		uint16_t LockAddress(PVOID64 addr) {
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

		bool UnlockAddress(PVOID64 addr, uint16_t instr) {
			return WriteMemory(addr, &instr, 2, true);
		}

		/*
		* Thread
		*/
		bool SuspendThread(HANDLE thread) {
			return ::SuspendThread(thread);
		}

		bool ResumeThread(HANDLE thread) {
			return ::ResumeThread(thread);
		}

		uint16_t BlockThread(HANDLE thread) {
			if (!SuspendThread(thread)) {
				return 0;
			}
			unsigned char jmpSelf[] = { 0xeb, 0xfe };
			bool isX86;
			auto contextBuf = GetThreadContext(thread, &isX86);
			PVOID64 ip;
			if (isX86) {
				auto context = (_CONTEXT32*)contextBuf.data();
				ip = (PVOID64)context->Eip;
			} else {
				auto context = (_CONTEXT64*)contextBuf.data();
				ip = (PVOID64)context->Rip;
			}
			auto oldInstr = LockAddress(ip);
			ResumeThread(thread);
			return oldInstr;
		}

		bool ResumeBlockedThread(HANDLE thread, uint16_t instr) {
			if (!SuspendThread(thread)) {
				return false;
			}
			uint16_t oldInstr;
			bool isX86;
			auto contextBuf = GetThreadContext(thread, &isX86);
			PVOID64 ip;
			if (isX86) {
				auto context = (_CONTEXT32*)contextBuf.data();
				ip = (PVOID64)context->Eip;
			}
			else {
				auto context = (_CONTEXT64*)contextBuf.data();
				ip = (PVOID64)context->Rip;
			}
			auto success = UnlockAddress(ip, instr);
			ResumeThread(thread);
			return success;
		}
		
		bool IsTheOwningThread(HANDLE thread) {
			return GetProcessIdOfThread(thread) == GetId();
		}

		std::vector<char> GetThreadContext(HANDLE thread, bool* isX86 = nullptr, DWORD flags = CONTEXT_CONTROL | CONTEXT64_INTEGER) {
			std::vector<char> context;
			bool success;
			if (!IsTheOwningThread(thread)) {
				return context;
			}
			if (ms_wow64.Wow64Operation(Get())) {
				context.resize(sizeof(_CONTEXT64));
				((_CONTEXT64*)context.data())->ContextFlags = flags;
				success = ms_wow64.GetThreadContext64(thread, (_CONTEXT64*)context.data());
				if (isX86) *isX86 = false;
			}
			else {
				if (IsX86() && !CurIsX86()) {
					if (isX86) *isX86 = true;
					context.resize(sizeof(WOW64_CONTEXT));
					((WOW64_CONTEXT*)context.data())->ContextFlags = flags;
					success = ::Wow64GetThreadContext(thread, (PWOW64_CONTEXT)context.data());
				}
				else {
					if (isX86) *isX86 = false;
					context.resize(sizeof(CONTEXT));
					((CONTEXT*)context.data())->ContextFlags = flags;
					success = ::GetThreadContext(thread, (LPCONTEXT)context.data());
				}
			}
			if (!success) {
				context.clear();
			}
			return context;
		}

		/*
		* Module
		*/
		
		std::vector<LDR_DATA_TABLE_ENTRY32> GetModuleList32() {
			/*
			* https://blog.csdn.net/wh445306/article/details/107867375
			*/

			std::vector<LDR_DATA_TABLE_ENTRY32> moduleList;
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
				wchar_t ProPath32[256];

				if (!ReadProcessMemory(Get(), (PVOID)(pbi32.PebBaseAddress + offsetof(PEB32, Ldr)), &Ldr32, sizeof(Ldr32), NULL)) {
					break;
				}
				if (!ReadProcessMemory(Get(), (PVOID)(Ldr32 + offsetof(PEB_LDR_DATA32, InLoadOrderModuleList)), &ListEntry32, sizeof(ListEntry32), NULL)) {
					break;
				}
				if (!ReadProcessMemory(Get(), (PVOID)(ListEntry32.Flink), &LDTE32, sizeof(LDTE32), NULL)) {
					break;
				}
				while (1) {
					if (LDTE32.InLoadOrderLinks.Flink == ListEntry32.Flink) break;
					if (ReadProcessMemory(Get(), (PVOID)LDTE32.FullDllName.Buffer, ProPath32, sizeof(ProPath32), NULL)) {
						// printf("模块基址:0x%X\t模块大小:0x%X\t模块路径:%ls\n", LDTE32.DllBase, LDTE32.SizeOfImage, ProPath32);
						moduleList.push_back(LDTE32);
					}
					if (!ReadProcessMemory(Get(), (PVOID)LDTE32.InLoadOrderLinks.Flink, &LDTE32, sizeof(LDTE32), NULL)) break;
				}
			} while (false);
			return moduleList;
		}

		std::vector<LDR_DATA_TABLE_ENTRY64> GetModuleList64() {
			/*
			* https://blog.csdn.net/wh445306/article/details/107867375
			*/
			std::vector<LDR_DATA_TABLE_ENTRY64> moduleList;
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

				if (!ReadMemory((PVOID64)(pbi64.PebBaseAddress + offsetof(PEB64, Ldr)), &Ldr64, sizeof(Ldr64))) {
					break;
				}
				if (!ReadMemory((PVOID64)(Ldr64 + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList)), &ListEntry64, sizeof(LIST_ENTRY64))) {
					break;
				}
				if (!ReadMemory((PVOID64)(ListEntry64.Flink), &LDTE64, sizeof(LDTE64))) {
					break;
				}

				while (1) {
					if (LDTE64.InLoadOrderLinks.Flink == ListEntry64.Flink) break;
					if (ReadMemory((PVOID64)LDTE64.FullDllName.Buffer, ProPath64, sizeof(ProPath64))) {
						// printf("模块基址:0x%llX\t模块大小:0x%X\t模块路径:%ls\n", LDTE64.DllBase, LDTE64.SizeOfImage, ProPath64);
						moduleList.push_back(LDTE64);
					}
					if (!ReadMemory((PVOID64)LDTE64.InLoadOrderLinks.Flink, &LDTE64, sizeof(LDTE64))) break;
				}
				
			} while (false);
			return moduleList;
		}

		bool FindModlueByModuleName32(const WCHAR* name, LDR_DATA_TABLE_ENTRY32* entry) {
			std::wstring name_ = name;
			for (auto& it : GetModuleList32()) {
				std::vector<char> buf;
				ReadMemory((PVOID64)it.BaseDllName.Buffer, &buf, it.BaseDllName.Length);
				WCHAR* dllName = (WCHAR*)buf.data();
				_wcsupr(dllName);
				_wcsupr((LPWSTR)name_.c_str());
				if (!wcscmp(dllName, (LPWSTR)name_.c_str())) {
					if (entry) memcpy(entry, &it, sizeof(it));
					return true;
				}
			}
			return false;
		}

		bool FindModlueByModuleName64(const WCHAR* name, LDR_DATA_TABLE_ENTRY64* entry) {
			std::wstring name_ = name;
			auto moduleList = GetModuleList64();
			for (auto& it : moduleList) {
				auto buf = ReadMemory((PVOID64)it.BaseDllName.Buffer, it.BaseDllName.Length + 2);
				WCHAR* dllName = (WCHAR*)buf.data();
				_wcsupr(dllName);
				_wcsupr((LPWSTR)name_.c_str());
				if (!wcscmp(dllName, (LPWSTR)name_.c_str())) {
					if (entry) memcpy(entry, &it, sizeof(it));
					return true;
				}
			}
			return false;
		}

		/*
		* other
		*/

	public:
		inline static const HANDLE kCurrentProcess = (HANDLE)-1;

	private:
		UniqueHandle m_handle;

	private:
		inline static Wow64 ms_wow64;

	public:

		static bool CurIsX86() {
			Process process;
			return process.IsX86();
		}

		static DWORD GetProcessIdOfThread(HANDLE thread) {
			return ::GetProcessIdOfThread(thread);
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

		static DWORD GetProcessIdByProcessName(const std::wstring& processName) {
			auto processEntryList = GetProcessList();
			std::wstring processName_ = processName;
			if (processEntryList.empty()) {
				return NULL;
			}
			for (auto& entry : processEntryList) {
				_wcsupr(entry.szExeFile);
				_wcsupr((LPWSTR)processName_.c_str());
				if (!wcscmp(entry.szExeFile, (LPWSTR)processName_.c_str()))
					return entry.th32ProcessID;
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
