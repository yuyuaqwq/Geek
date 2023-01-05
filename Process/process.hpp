#ifndef GEEK_PROCESS_H_
#define GEEK_PROCESS_H_

#include <exception>
#include <string>
#include <vector>

#include <Process/ntinc.h>

#include <Handle/handle.hpp>
#include <wow64ext/wow64ext.hpp>



namespace geek {
	

class Process {
public:
	enum class Status {
		kOk,
		kProcessInvalid,
		kOpenProcessError,
		kCreateProcessError,
		kIsWow64ProcessError,
		kMemoryError,
	};

public:
	void Open(HANDLE hProcess) {
		m_handle = UniqueHandle(hProcess);
	}

	void Open(UniqueHandle hProcess) {
		m_handle = std::move(hProcess);
	}

	Status Open(DWORD pid, DWORD desiredAccess = PROCESS_ALL_ACCESS) {
		auto hProcess = OpenProcess(desiredAccess, FALSE, pid);
		if (hProcess == NULL) {
			return Status::kOpenProcessError;
		}
		m_handle = UniqueHandle(hProcess);
		return Status::kOk;
	}

	// CREATE_SUSPENDED:创建挂起进程
	Status Open(const std::wstring& command, DWORD creationFlags = 0) {
		std::vector<wchar_t> buf(command.size() + 1);
		memcpy(buf.data(), command.c_str(), command.size() + 1);
		STARTUPINFOW startupInfo{ sizeof(startupInfo) };
		PROCESS_INFORMATION processInformation{ 0 };
		if (!CreateProcessW(NULL, buf.data(), NULL, NULL, NULL, creationFlags, NULL, NULL, &startupInfo, &processInformation)) {
			return Status::kOpenProcessError;
		}
		m_handle = UniqueHandle(processInformation.hProcess);
		CloseHandle(processInformation.hThread);
		return Status::kOk;
	}

	HANDLE Get() const noexcept {
		if (this == nullptr) {
			return (HANDLE)-1;
		}
		return m_handle.Get();
	}

	Status IsX86(bool* res) const {
		auto handle = Get();
		if (handle == NULL) {
			return Status::kProcessInvalid;
		}

		::BOOL IsWow64;
		if (!::IsWow64Process(handle, &IsWow64)) {
			return Status::kIsWow64ProcessError;
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

		return Status::kIsWow64ProcessError;

	}


	// VirtualMemory
	void* AllocMemory(void* addr, size_t len, DWORD type = MEM_COMMIT, DWORD protect = PAGE_READWRITE) {
		return VirtualAllocEx(Get(), addr, len, type, protect);
	}

	void* AllocMemory(size_t len, DWORD type = MEM_COMMIT, DWORD protect = PAGE_READWRITE) {
		return AllocMemory(len, type, protect);
	}

	Status ReadMemory(PVOID64 addr, size_t len, std::vector<char>* buf) {
		buf->resize(len);
		if (this == nullptr) {
			memcpy(buf->data(), (void*)addr, len);
			return Status::kOk;
		}
		SIZE_T readByte;

		if (WOW64::WOW64Operation(Get())) {
			HMODULE NtdllModule = GetModuleHandle(L"ntdll.dll");
			pfnNtWow64QueryInformationProcess64 NtWow64QueryInformationProcess64 = (pfnNtWow64QueryInformationProcess64)GetProcAddress(NtdllModule, "NtWow64QueryInformationProcess64");
			pfnNtWow64ReadVirtualMemory64 NtWow64ReadVirtualMemory64 = (pfnNtWow64ReadVirtualMemory64)GetProcAddress(NtdllModule, "NtWow64ReadVirtualMemory64");
			if (!NT_SUCCESS(NtWow64ReadVirtualMemory64(Get(), addr, buf->data(), len, NULL))) {
				return Status::kMemoryError;
			}
		}
		else {
			if (!ReadProcessMemory(Get(), (void*)addr, buf->data(), len, &readByte)) {
				// throw ProcessException(ProcessException::Type::kReadProcessMemoryError);
				return Status::kMemoryError;
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
		if (WOW64::WOW64Operation(Get())) {
			HMODULE NtdllModule = GetModuleHandle(L"ntdll.dll");
			pfnNtWow64QueryInformationProcess64 NtWow64QueryInformationProcess64 = (pfnNtWow64QueryInformationProcess64)GetProcAddress(NtdllModule, "NtWow64QueryInformationProcess64");
			pfnNtWow64WriteVirtualMemory64 NtWow64WriteVirtualMemory64 = (pfnNtWow64WriteVirtualMemory64)GetProcAddress(NtdllModule, "NtWow64WriteVirtualMemory64");
			if (!NT_SUCCESS(NtWow64WriteVirtualMemory64(Get(), addr, (PVOID)buf, len, NULL))) {
				return Status::kMemoryError;
			}
		}
		else {
			if (!WriteProcessMemory(Get(), addr, buf, len, &readByte)) {
				// throw ProcessException(ProcessException::Type::kWriteProcessMemoryError);
				return Status::kMemoryError;
			}
		}
	}

	Status SetMemoryProtect(void* addr, size_t len, DWORD newProtect, DWORD* oldProtect) {
		bool success = false;
		if (this == nullptr) {
			success = VirtualProtect(addr, len, newProtect, oldProtect);
		}
		else {
			success = VirtualProtectEx(Get(), addr, len, newProtect, oldProtect);
		}
		if (!success) {
			return Status::kMemoryError;
		}
		return Status::kOk;
	}

	// Module
	Status GetModuleList() {

		/*
		* https://blog.csdn.net/wh445306/article/details/107867375
		*/

		Status status = Status::kOk;
		do {
			if (WOW64::WOW64Operation(Get())) {
				HMODULE NtdllModule = GetModuleHandle(L"ntdll.dll");
				pfnNtWow64QueryInformationProcess64 NtWow64QueryInformationProcess64 = (pfnNtWow64QueryInformationProcess64)GetProcAddress(NtdllModule, "NtWow64QueryInformationProcess64");
				pfnNtWow64ReadVirtualMemory64 NtWow64ReadVirtualMemory64 = (pfnNtWow64ReadVirtualMemory64)GetProcAddress(NtdllModule, "NtWow64ReadVirtualMemory64");
				PROCESS_BASIC_INFORMATION64 pbi64 = { 0 };

				status = Status::kMemoryError;
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
						printf("模块基址:0x%llX\t模块大小:0x%X\t模块路径:%ls\n", LDTE64.DllBase, LDTE64.SizeOfImage, ProPath64);
					}
					if (!NT_SUCCESS(NtWow64ReadVirtualMemory64(Get(), (PVOID64)LDTE64.InLoadOrderLinks.Flink, &LDTE64, sizeof(_LDR_DATA_TABLE_ENTRY64), NULL))) break;
				}
				status = Status::kOk;
			}
			else {
				HMODULE NtdllModule = GetModuleHandle(L"ntdll.dll");
				pfnNtQueryInformationProcess NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(NtdllModule, "NtQueryInformationProcess");
				PROCESS_BASIC_INFORMATION32 pbi32 = { 0 };

				status = Status::kMemoryError;

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
						printf("模块基址:0x%X\t模块大小:0x%X\t模块路径:%ls\n", LDTE32.DllBase, LDTE32.SizeOfImage, ProPath32);
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
	UniqueHandle m_handle;
};

} // namespace geek

#endif // GEEK_PROCESS_H_
