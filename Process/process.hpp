#ifndef GEEK_PROCESS_H_
#define GEEK_PROCESS_H_

#include <exception>
#include <string>
#include <vector>

#include <Handle/handle.hpp>




namespace geek {
	


class Process {
public:
	enum class Status {
		kOk,
		kProcessInvalid,
		kOpenProcessError,
		kCreateProcessError,
		kIsWow64ProcessError,
		kReadProcessMemoryError,
		kWriteProcessMemoryError,
		kVirtualProtectError,
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

	Status ReadMemory(void* addr, size_t len, std::vector<char>* buf) {
		buf->resize(len);
		std::vector<char> buf(len);
		if (this == nullptr) {
			memcpy(buf->data(), addr, len);
			return Status::kOk;
		}
		SIZE_T readByte;
		if (!ReadProcessMemory(Get(), addr, buf->data(), len, &readByte)) {
			// throw ProcessException(ProcessException::Type::kReadProcessMemoryError);
			return Status::kReadProcessMemoryError;
		}
		return Status::kOk;
	}

	Status WriteMemory(void* addr, const void* buf, size_t len) {
		if (this == nullptr) {
			memcpy(addr, buf, len);
			return;
		}
		SIZE_T readByte;
		if (!WriteProcessMemory(Get(), addr, buf, len, &readByte)) {
			// throw ProcessException(ProcessException::Type::kWriteProcessMemoryError);
			return Status::kWriteProcessMemoryError;
		}
	}

	Status SetProtect(void* addr, size_t len, DWORD newProtect, DWORD* oldProtect) {
		bool success = false;
		if (this == nullptr) {
			success = VirtualProtect(addr, len, newProtect, oldProtect);
		}
		else {
			success = VirtualProtectEx(Get(), addr, len, newProtect, oldProtect);
		}
		if (!success) {
			return Status::kVirtualProtectError;
		}
		return Status::kOk;
	}


public:
	inline static const HANDLE kCurrentProcess = (HANDLE)-1;

private:
	UniqueHandle m_handle;
};

} // namespace geek

#endif // GEEK_PROCESS_H_
