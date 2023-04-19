#ifndef GEEK_PROCESS_PROCESS_H_
#define GEEK_PROCESS_PROCESS_H_

#include <string>
#include <vector>

#include <Windows.h>
#include <tlhelp32.h>

#include <Geek/Process/ntinc.h>
#include <Geek/Handle/handle.hpp>
#include <Geek/Module/module.hpp>
#include <Geek/PE/image.hpp>
#include <Geek/Thread/thread.hpp>
#include <Geek/wow64ext/wow64ext.hpp>

#include <CppUtils/String/string.hpp>

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
	* CREATE_SUSPENDED:�����������
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
		LUID v1;//Ȩ�����ͣ����ض��б�ʶ
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
		::GetNativeSystemInfo(&SystemInfo);		//���ϵͳ��Ϣ
		if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {		//�õ�ϵͳλ��64
			return false;
		}
		else if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {		// �õ�ϵͳλ��32
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
	PVOID64 AllocMemory(PVOID64 addr, size_t len, DWORD type = MEM_RESERVE | MEM_COMMIT, DWORD protect = PAGE_READWRITE) {
		if (ms_wow64.Wow64Operation(Get())) {
			return (PVOID64)ms_wow64.VirtualAllocEx64(Get(), (DWORD64)addr, len, type, protect);
		}
		return VirtualAllocEx(Get(), addr, len, type, protect);
	}

	PVOID64 AllocMemory(size_t len, DWORD type = MEM_RESERVE | MEM_COMMIT, DWORD protect = PAGE_READWRITE) {
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

		// ��ʼ�� vector ����
		memoryBlockList.reserve(200);

		// ��ȡ PageSize �͵�ַ����
		SYSTEM_INFO sysInfo = { 0 };
		GetSystemInfo(&sysInfo);
		/*
		typedef struct _SYSTEM_INFO {
		union {
		DWORD dwOemId;							// �����Ա���
		struct {
		WORD wProcessorArchitecture;			// ����ϵͳ��������ϵ�ṹ
		WORD wReserved;						// ����
		} DUMMYSTRUCTNAME;
		} DUMMYUNIONNAME;
		DWORD     dwPageSize;						// ҳ���С��ҳ�汣���ͳ�ŵ������
		LPVOID    lpMinimumApplicationAddress;	// ָ��Ӧ�ó����dll�ɷ��ʵ�����ڴ��ַ��ָ��
		LPVOID    lpMaximumApplicationAddress;	// ָ��Ӧ�ó����dll�ɷ��ʵ�����ڴ��ַ��ָ��
		DWORD_PTR dwActiveProcessorMask;			// ����������
		DWORD     dwNumberOfProcessors;			// ��ǰ�����߼�������������
		DWORD     dwProcessorType;				// ���������ͣ������Ա���
		DWORD     dwAllocationGranularity;		// �����ڴ����ʼ��ַ������
		WORD      wProcessorLevel;				// ����������
		WORD      wProcessorRevision;				// �������޶�
		} SYSTEM_INFO, *LPSYSTEM_INFO;
		*/

		//�����ڴ�
		const char* p = (const char*)sysInfo.lpMinimumApplicationAddress;
		MEMORY_BASIC_INFORMATION  memInfo = { 0 };
		while (p < sysInfo.lpMaximumApplicationAddress) {
			// ��ȡ���������ڴ�黺�����ֽ���
			size_t size = VirtualQueryEx(Get(), p, &memInfo, sizeof(MEMORY_BASIC_INFORMATION));
			if (size != sizeof(MEMORY_BASIC_INFORMATION)) { break; }

			// ���ڴ����Ϣ׷�ӵ� vector ����β��
			memoryBlockList.push_back(memInfo);

			// �ƶ�ָ��
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

	bool MemoryEnum(bool(*callback)(char* addr, size_t size, void* arg), void* arg) const {
		bool success = false;
		std::vector<char> buf;
		do {
			std::vector<MODULEENTRY32> modulelist = EnumAllProcessModules();
			std::vector<MEMORY_BASIC_INFORMATION> vec = EnumAllMemoryBlocks();

			// �����ý��̵��ڴ��
			size_t sizeSum = 0;
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
				SIZE_T readCount = 0;
				if (!ReadProcessMemory(Get(), vec[i].BaseAddress, tempBuff.data(), vec[i].RegionSize, &readCount)) {
					//printf("%d\n", GetLastError());
					continue;
				}
				//printf("%x/%x\n", vec[i].BaseAddress, vec[i].RegionSize);
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
		PVOID64 ip;
		if (isX86) {
			auto context = (_CONTEXT32*)contextBuf.data();
			ip = (PVOID64)context->Eip;
		}
		else {
			auto context = (_CONTEXT64*)contextBuf.data();
			ip = (PVOID64)context->Rip;
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



	/*
	* Image
	*/
	static void* LoadLibraryDefault(Process* process, const char* lib_name) {
		if (process->IsCur()) {
			return LoadLibraryA(lib_name);
		}
		void* addr = NULL;
		auto len = strlen(lib_name) + 1;
		auto lib_name_buf = process->AllocMemory(len);

		do {
			if (!lib_name_buf) {
				break;
			}
			if (!process->WriteMemory((PVOID64)lib_name_buf, lib_name, len)) {
				break;
			}
			auto thread = process->CreateThread((PTHREAD_START_ROUTINE)LoadLibraryA, (PVOID64)lib_name_buf);
			if (thread.IsCur()) {
				break;
			}
			thread.WaitExit(INFINITE);
			addr = (void*)thread.GetExitCode();
		} while (false);
		if (lib_name_buf) {
			process->FreeMemory(lib_name_buf);
		}
		return addr;
	}


	void* LoadLibraryFromImage(Image* image, bool call_dll_entry = true, uint64_t init_parameter = 0) {
		if (IsX86() != image->IsPE32()) {
			return nullptr;
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
			if (!image->RepairImportAddressTable((Image::LoadLibraryFunc)LoadLibraryDefault, this)) {
				break;
			}
			auto image_buf = image->SaveToImageBuf((uint64_t)image_base, true);
			if (call_dll_entry) {
				if (IsCur()) {
					if (!WriteMemory(image_base, image_buf.data(), image_buf.size())) {
						break;
					}
					image->ExecuteTls((uint64_t)image_base);
					image->CallEntryPoint((uint64_t)image_base, init_parameter);
				}
				else {
					uint64_t entry_point = (uint64_t)image_base + image->GetEntryPoint();
					if (image->IsPE32()) {
						int offset = 0;
						image_buf[offset++] = 0x68;		// push 0
						*(uint32_t*)&image_buf[offset] = (uint32_t)init_parameter;
						offset += 4;

						image_buf[offset++] = 0x68;		// push DLL_PROCESS_ATTACH
						*(uint32_t*)&image_buf[offset] = DLL_PROCESS_ATTACH;
						offset += 4;

						image_buf[offset++] = 0x68;		// push image_base
						*(uint32_t*)&image_buf[offset] = (uint32_t)image_base;
						offset += 4;

						image_buf[offset++] = 0xb8;		// mov eax, entry_point
						*(uint32_t*)&image_buf[offset] = (uint32_t)entry_point;
						offset += 4;

						image_buf[offset++] = 0xff;		// call eax
						image_buf[offset++] = 0xd0;

						image_buf[offset++] = 0xc2;		// ret 4
						*(uint16_t*)&image_buf[offset] = 4;
						offset += 2;
					}
					else {
						/*
						* 64λ�£�ջ��Ҫ16�ֽڶ��룬������һЩָ���쳣(��movaps)
						* ��Ϊ����һ��callѹ��ķ��ص�ַ������-28
						*/
						int offset = 0;
						image_buf[offset++] = 0x48;		// sub rsp, 28
						image_buf[offset++] = 0x83;
						image_buf[offset++] = 0xec;
						image_buf[offset++] = 0x28;

						// ���ݲ���
						image_buf[offset++] = 0x48;		// mov rcx, image_base
						image_buf[offset++] = 0xb9;
						*(uint64_t*)&image_buf[offset] = (uint64_t)image_base;
						offset += 8;

						image_buf[offset++] = 0x48;		// mov rdx, DLL_PROCESS_ATTACH
						image_buf[offset++] = 0xc7;
						image_buf[offset++] = 0xc2;
						*(uint32_t*)&image_buf[offset] = 1;
						offset += 4;

						image_buf[offset++] = 0x49;		// mov r8, init_parameter
						image_buf[offset++] = 0xb8;
						*(uint64_t*)&image_buf[offset] = init_parameter;
						offset += 8;


						image_buf[offset++] = 0x48;		// mov rax, entry_point
						image_buf[offset++] = 0xb8;
						*(uint64_t*)&image_buf[offset] = entry_point;
						offset += 8;

						image_buf[offset++] = 0xff;		// call rax
						image_buf[offset++] = 0xd0;

						// ����ջ�ռ�
						image_buf[offset++] = 0x48;		// add rsp, 28
						image_buf[offset++] = 0x83;
						image_buf[offset++] = 0xc4;
						image_buf[offset++] = 0x28;

						image_buf[offset++] = 0xc3;		// ret
					}
					if (!WriteMemory(image_base, image_buf.data(), image_buf.size())) {
						break;
					}

					CreateThread((PTHREAD_START_ROUTINE)image_base, NULL);
				}
			}
			success = true;
		} while (false);
		if (success == false && image_base) {
			FreeMemory(image_base);
		}
		return image_base;
	}

	
	/*
	* Module
	*/
	std::vector<Module> GetModuleList() {
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

				if (!ReadMemory((PVOID)(pbi32.PebBaseAddress + offsetof(PEB32, Ldr)), &Ldr32, sizeof(Ldr32))) {
					break;
				}
				if (!ReadMemory((PVOID)(Ldr32 + offsetof(PEB_LDR_DATA32, InLoadOrderModuleList)), &ListEntry32, sizeof(ListEntry32))) {
					break;
				}
				if (!ReadMemory((PVOID)(ListEntry32.Flink), &LDTE32, sizeof(LDTE32))) {
					break;
				}

				while (true) {
					if (LDTE32.InLoadOrderLinks.Flink == ListEntry32.Flink) break;
					std::vector<wchar_t>  full_name(LDTE32.FullDllName.Length + 1, 0);
					if (!ReadMemory((PVOID)LDTE32.FullDllName.Buffer, (wchar_t*)full_name.data(), LDTE32.FullDllName.Length)) {
						continue;
					}
					std::vector<wchar_t>  base_name(LDTE32.BaseDllName.Length + 1, 0);
					if (!ReadMemory((PVOID)LDTE32.BaseDllName.Buffer, (wchar_t*)base_name.data(), LDTE32.BaseDllName.Length)) {
						continue;
					}
					Module module(LDTE32, base_name.data(), full_name.data());
					moduleList.push_back(module);
					if (!ReadMemory((PVOID)LDTE32.InLoadOrderLinks.Flink, &LDTE32, sizeof(LDTE32))) break;
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

				if (!ReadMemory((PVOID64)(pbi64.PebBaseAddress + offsetof(PEB64, Ldr)), &Ldr64, sizeof(Ldr64))) {
					break;
				}
				if (!ReadMemory((PVOID64)(Ldr64 + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList)), &ListEntry64, sizeof(LIST_ENTRY64))) {
					break;
				}
				if (!ReadMemory((PVOID64)(ListEntry64.Flink), &LDTE64, sizeof(LDTE64))) {
					break;
				}

				while (true) {
					if (LDTE64.InLoadOrderLinks.Flink == ListEntry64.Flink) break;
					std::vector<wchar_t> full_name(LDTE64.FullDllName.Length + 1, 0);
					if (!ReadMemory((PVOID64)LDTE64.FullDllName.Buffer, (wchar_t*)full_name.data(), LDTE64.FullDllName.Length)) {
						if (!ReadMemory((PVOID64)LDTE64.InLoadOrderLinks.Flink, &LDTE64, sizeof(LDTE64))) break;
						continue;
					}
					std::vector<wchar_t> base_name(LDTE64.BaseDllName.Length + 1, 0);
					if (!ReadMemory((PVOID64)LDTE64.BaseDllName.Buffer, (wchar_t*)base_name.data(), LDTE64.BaseDllName.Length)) {
						if (!ReadMemory((PVOID64)LDTE64.InLoadOrderLinks.Flink, &LDTE64, sizeof(LDTE64))) break;
						continue;
					}
					Module module(LDTE64, base_name.data(), full_name.data());
					moduleList.push_back(module);
					if (!ReadMemory((PVOID64)LDTE64.InLoadOrderLinks.Flink, &LDTE64, sizeof(LDTE64))) break;
				}

			} while (false);
		}
		return moduleList;
	}

	bool FindModlueByModuleName(const std::wstring& name, Module* module = nullptr) {
		std::wstring find_name = CppUtils::String::ToUppercase(name);
		for (auto& it : GetModuleList()) {
			auto base_name_up = CppUtils::String::ToUppercase(it.base_name);
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
			//������Դ

			HRSRC hResID = FindResourceW(hModule, MAKEINTRESOURCEW(ResourceID), type);
			if (!hResID) {
				break;
			}
			//������Դ  
			HGLOBAL hRes = LoadResource(hModule, hResID);
			if (!hRes) {
				break;
			}
			//������Դ
			LPVOID pRes = LockResource(hRes);
			if (pRes == NULL)
			{
				break;
			}
			//�õ����ͷ���Դ�ļ���С 
			unsigned long dwResSize = SizeofResource(hModule, hResID);
			//�����ļ� 
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
				// Log(LogLevel::LOG_ERROR, Cmd::CMD_UPLOAD_ACCOUNTS_INFO, "[KeePass.SaveFileFromResource] WriteFile error:%d\n", GetLastError());
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

	static DWORD GetProcessIdByProcessName(const std::wstring& processName, int count = 1) {
		auto processEntryList = GetProcessList();
		std::wstring processName_ = processName;
		if (processEntryList.empty()) {
			return NULL;
		}
		int i = 0;
		for (auto& entry : processEntryList) {
			auto exeFile_str = CppUtils::String::ToUppercase(std::wstring(entry.szExeFile));
			processName_ = CppUtils::String::ToUppercase(processName_);
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
