#ifndef GEEK_PROCESS_H_
#define GEEK_PROCESS_H_

#include <exception>
#include <string>
#include <vector>

#include <Windows.h>
#include <tlhelp32.h>

#include <Geek/Process/ntinc.h>
#include <Geek/Handle/handle.hpp>
#include <Geek/wow64ext/wow64ext.hpp>

namespace geek {
	
class Process {
public:
	enum class Status {
		kOk,
		kProcessInvalid,
		kApiCallFailed,
	};

public:
	void Open(HANDLE hProcess) {
		mHandle = UniqueHandle(hProcess);
	}

	void Open(UniqueHandle hProcess) {
		mHandle = std::move(hProcess);
	}

	Status Open(DWORD pid, DWORD desiredAccess = PROCESS_ALL_ACCESS) {
		auto hProcess = OpenProcess(desiredAccess, FALSE, pid);
		if (hProcess == NULL) {
			return Status::kApiCallFailed;
		}
		mHandle = UniqueHandle(hProcess);
		return Status::kOk;
	}

	/*
	* CREATE_SUSPENDED:创建挂起进程
	*/
	Status Create(const std::wstring& command, BOOL inheritHandles = FALSE, DWORD creationFlags = 0) {
		std::wstring command_ = command;
		STARTUPINFOW startupInfo{ sizeof(startupInfo) };
		PROCESS_INFORMATION processInformation{ 0 };
		if (!CreateProcessW(NULL, (LPWSTR)command_.c_str(), NULL, NULL, inheritHandles, creationFlags, NULL, NULL, &startupInfo, &processInformation)) {
			printf("%d", GetLastError());
			return Status::kApiCallFailed;
		}
		mHandle = UniqueHandle(processInformation.hProcess);
		CloseHandle(processInformation.hThread);
		return Status::kOk;
	}

	/*
	* L"explorer.exe"
	*/
	Status CreateByToken(const std::wstring& tokenProcessName, const std::wstring& command, BOOL inheritHandles = FALSE, DWORD creationFlags = 0, STARTUPINFOW* si = NULL, PROCESS_INFORMATION* pi = NULL) {
		HANDLE hToken_ = NULL;
		std::wstring tokenProcessName_ = tokenProcessName;
		DWORD pid = GetProcessIdByProcessName(tokenProcessName);
		if (pid == NULL) {
			return Status::kApiCallFailed;
		}
		UniqueHandle hProcess{ OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid) };
		OpenProcessToken(hProcess.Get(), TOKEN_ALL_ACCESS, &hToken_);
		if (hToken_ == NULL) {
			return Status::kApiCallFailed;
		}
		UniqueHandle hToken { hToken_ };

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
			return Status::kApiCallFailed;
		}
		mHandle = UniqueHandle(pi->hProcess);
		CloseHandle(pi->hThread);
		return Status::kOk;
	}

	HANDLE Get() const noexcept {
		if (this == nullptr) {
			return (HANDLE)-1;
		}
		return mHandle.Get();
	}

	Status IsX86(bool* res) const {
		auto handle = Get();
		if (handle == NULL) {
			return Status::kProcessInvalid;
		}

		::BOOL IsWow64;
		if (!::IsWow64Process(handle, &IsWow64)) {
			return Status::kApiCallFailed;
		}

		if (IsWow64) {
			*res = true;
			return Status::kOk;
		}

		::SYSTEM_INFO SystemInfo = { 0 };
		::GetNativeSystemInfo(&SystemInfo);		//获得系统信息
		if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {		//得到系统位数64
			*res = false;
			return Status::kOk;
		}
		else if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {		// 得到系统位数32
			*res = true;
			return Status::kOk;
		}

		return Status::kApiCallFailed;

	}


	// VirtualMemory
	PVOID64 AllocMemory(PVOID64 addr, size_t len, DWORD type = MEM_COMMIT, DWORD protect = PAGE_READWRITE) {
		if (msWOW64.WOW64Operation(Get())) {
			return (PVOID64)msWOW64.VirtualAllocEx64(Get(), (DWORD64)addr, len, type, protect);
		}
		return VirtualAllocEx(Get(), addr, len, type, protect);
	}

	PVOID64 AllocMemory(size_t len, DWORD type = MEM_COMMIT, DWORD protect = PAGE_READWRITE) {
		return AllocMemory(NULL, len, type, protect);
	}

	bool FreeMemory(PVOID64 addr, size_t size = 0, DWORD type = MEM_RELEASE) {
		if (msWOW64.WOW64Operation(Get())) {
			return msWOW64.VirtualFreeEx64(Get(), (DWORD64)addr, size, type);
		}
		return VirtualFreeEx(Get(), addr, size, type);
	}

	Status ReadMemory(PVOID64 addr, size_t len, std::vector<char>* buf) {
		buf->resize(len);
		if (this == nullptr) {
			memcpy(buf->data(), (void*)addr, len);
			return Status::kOk;
		}
		SIZE_T readByte;

		if (msWOW64.WOW64Operation(Get())) {
			HMODULE NtdllModule = GetModuleHandleW(L"ntdll.dll");
			pfnNtWow64QueryInformationProcess64 NtWow64QueryInformationProcess64 = (pfnNtWow64QueryInformationProcess64)GetProcAddress(NtdllModule, "NtWow64QueryInformationProcess64");
			pfnNtWow64ReadVirtualMemory64 NtWow64ReadVirtualMemory64 = (pfnNtWow64ReadVirtualMemory64)GetProcAddress(NtdllModule, "NtWow64ReadVirtualMemory64");
			if (!NT_SUCCESS(NtWow64ReadVirtualMemory64(Get(), addr, buf->data(), len, NULL))) {
				return Status::kApiCallFailed;
			}
		}
		else {
			if (!ReadProcessMemory(Get(), (void*)addr, buf->data(), len, &readByte)) {
				// throw ProcessException(ProcessException::Type::kReadProcessMemoryError);
				return Status::kApiCallFailed;
			}
		}
		
		return Status::kOk;
	}

	Status WriteMemory(PVOID64 addr, const void* buf, size_t len) {
		if (this == nullptr) {
			memcpy(addr, buf, len);
			return Status::kOk;
		}
		SIZE_T readByte;
		if (msWOW64.WOW64Operation(Get())) {
			HMODULE NtdllModule = GetModuleHandleW(L"ntdll.dll");
			pfnNtWow64QueryInformationProcess64 NtWow64QueryInformationProcess64 = (pfnNtWow64QueryInformationProcess64)GetProcAddress(NtdllModule, "NtWow64QueryInformationProcess64");
			pfnNtWow64WriteVirtualMemory64 NtWow64WriteVirtualMemory64 = (pfnNtWow64WriteVirtualMemory64)GetProcAddress(NtdllModule, "NtWow64WriteVirtualMemory64");
			if (!NT_SUCCESS(NtWow64WriteVirtualMemory64(Get(), addr, (PVOID)buf, len, NULL))) {
				return Status::kApiCallFailed;
			}
		}
		else {
			if (!WriteProcessMemory(Get(), addr, buf, len, &readByte)) {
				return Status::kApiCallFailed;
			}
		}
		return Status::kOk;
	}

	Status SetMemoryProtect(PVOID64 addr, size_t len, DWORD newProtect, DWORD* oldProtect) {
		bool success = false;
		if (msWOW64.WOW64Operation(Get())) {
			success = msWOW64.VirtualProtectEx64(Get(), (DWORD64)addr, len, newProtect, oldProtect);
		} else {
			success = VirtualProtectEx(Get(), addr, len, newProtect, oldProtect);
		}
		if (!success) {
			return Status::kApiCallFailed;
		}
		return Status::kOk;
	}

	Status GetThreadContext64(HANDLE thread, _CONTEXT64* context) {
		bool success = false;
		if (msWOW64.WOW64Operation(Get())) {
			success = msWOW64.GetThreadContext64(thread, context);
		}
		else {
			::GetThreadContext(thread, context);
		}
	}

	// Module
	Status GetModuleList() {

		/*
		* https://blog.csdn.net/wh445306/article/details/107867375
		*/

		Status status = Status::kOk;
		do {
			if (msWOW64.WOW64Operation(Get())) {
				HMODULE NtdllModule = GetModuleHandleW(L"ntdll.dll");
				pfnNtWow64QueryInformationProcess64 NtWow64QueryInformationProcess64 = (pfnNtWow64QueryInformationProcess64)GetProcAddress(NtdllModule, "NtWow64QueryInformationProcess64");
				pfnNtWow64ReadVirtualMemory64 NtWow64ReadVirtualMemory64 = (pfnNtWow64ReadVirtualMemory64)GetProcAddress(NtdllModule, "NtWow64ReadVirtualMemory64");
				PROCESS_BASIC_INFORMATION64 pbi64 = { 0 };

				status = Status::kApiCallFailed;
				if (!NT_SUCCESS(NtWow64QueryInformationProcess64(Get(), ProcessBasicInformation, &pbi64, sizeof(pbi64), NULL))) {
					break;
				}
				DWORD64 Ldr64 = 0;
				LIST_ENTRY64 ListEntry64 = { 0 };
				LDR_DATA_TABLE_ENTRY64 LDTE64 = { 0 };
				wchar_t ProPath64[256];

				if (!NT_SUCCESS(NtWow64ReadVirtualMemory64(Get(), (PVOID64)(pbi64.PebBaseAddress + offsetof(PEB64, Ldr)), &Ldr64, sizeof(Ldr64), NULL))) {
					break;
				}
				if (!NT_SUCCESS(NtWow64ReadVirtualMemory64(Get(), (PVOID64)(Ldr64 + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList)), &ListEntry64, sizeof(LIST_ENTRY64), NULL))) {
					break;
				}
				if (!NT_SUCCESS(NtWow64ReadVirtualMemory64(Get(), (PVOID64)(ListEntry64.Flink), &LDTE64, sizeof(_LDR_DATA_TABLE_ENTRY64), NULL))) {
					break;
				}

				while (1) {
					if (LDTE64.InLoadOrderLinks.Flink == ListEntry64.Flink) break;
					if (NT_SUCCESS(NtWow64ReadVirtualMemory64(Get(), (PVOID64)LDTE64.FullDllName.Buffer, ProPath64, sizeof(ProPath64), NULL))) {
						// printf("模块基址:0x%llX\t模块大小:0x%X\t模块路径:%ls\n", LDTE64.DllBase, LDTE64.SizeOfImage, ProPath64);

					}
					if (!NT_SUCCESS(NtWow64ReadVirtualMemory64(Get(), (PVOID64)LDTE64.InLoadOrderLinks.Flink, &LDTE64, sizeof(_LDR_DATA_TABLE_ENTRY64), NULL))) break;
				}
				status = Status::kOk;
			}
			else {
				HMODULE NtdllModule = GetModuleHandleW(L"ntdll.dll");
				pfnNtQueryInformationProcess NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(NtdllModule, "NtQueryInformationProcess");
				PROCESS_BASIC_INFORMATION32 pbi32 = { 0 };

				status = Status::kApiCallFailed;

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
				if (!ReadProcessMemory(Get(), (PVOID)(Ldr32 + offsetof(PEB_LDR_DATA32, InLoadOrderModuleList)), &ListEntry32, sizeof(LIST_ENTRY32), NULL)) {
					break;
				}
				if (!ReadProcessMemory(Get(), (PVOID)(ListEntry32.Flink), &LDTE32, sizeof(_LDR_DATA_TABLE_ENTRY32), NULL)) {
					break;
				}
				while (1) {
					if (LDTE32.InLoadOrderLinks.Flink == ListEntry32.Flink) break;
					if (ReadProcessMemory(Get(), (PVOID)LDTE32.FullDllName.Buffer, ProPath32, sizeof(ProPath32), NULL)) {
						// printf("模块基址:0x%X\t模块大小:0x%X\t模块路径:%ls\n", LDTE32.DllBase, LDTE32.SizeOfImage, ProPath32);
					}
					if (!ReadProcessMemory(Get(), (PVOID)LDTE32.InLoadOrderLinks.Flink, &LDTE32, sizeof(_LDR_DATA_TABLE_ENTRY32), NULL)) break;
				}
				status = Status::kOk;
			}
		} while (false);
		return status;
	}


public:
	// inline static const HANDLE kCurrentProcess = (HANDLE)-1;

private:
	UniqueHandle mHandle;

private:
	inline static WOW64 msWOW64;

public:
	static Status GetProcessList(std::vector<PROCESSENTRY32W>* processEntryList) {
		PROCESSENTRY32W pe32 = { 0 };
		pe32.dwSize = sizeof(PROCESSENTRY32W);
		UniqueHandle hProcessSnap{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL) };
		if (!Process32FirstW(hProcessSnap.Get(), &pe32)) {
			return Status::kApiCallFailed;
		}
		do {
			processEntryList->push_back(pe32);
		} while (Process32NextW(hProcessSnap.Get(), &pe32));
		return Status::kOk;
	}

	static DWORD GetProcessIdByProcessName(const std::wstring& processName) {
		std::vector<PROCESSENTRY32W> processEntryList;
		auto status = GetProcessList(&processEntryList);
		std::wstring processName_ = processName;
		if (status != Status::kOk) {
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
};

} // namespace geek

#endif // GEEK_PROCESS_H_
