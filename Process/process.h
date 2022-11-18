#ifndef GEEK_PROCESS_H_
#define GEEK_PROCESS_H_

#include <exception>
#include <string>
#include <vector>

#include <Handle/handle.h>




namespace geek {
	

const HANDLE kCurrentProcess = (HANDLE)-1;


class ProcessException : public std::exception {
public:
	enum class Type {
		kProcessInvalid,
		kOpenProcessError,
		kCreateProcessError,
		kIsWow64ProcessError,
		kReadProcessMemoryError,
		kWriteProcessMemoryError,
		kVirtualProtectError,
	};

public:
	ProcessException(Type t_type, const char* t_msg = "") noexcept :  m_type{ m_type }, std::exception{ t_msg } {
		m_type = t_type;
	}

public:
	Type GetType() const noexcept {
		return m_type;
	}

private:
	Type m_type;
};

class Process {
public:
	explicit Process(HANDLE hProcess) {
		m_handle = UniqueHandle(hProcess);
	}

	explicit Process(UniqueHandle hProcess) {
		m_handle = std::move(hProcess);
	}

	explicit Process(DWORD pid, DWORD desiredAccess = PROCESS_ALL_ACCESS) {
		auto hProcess = OpenProcess(desiredAccess, FALSE, pid);
		if (hProcess == NULL) {
			throw ProcessException(ProcessException::Type::kOpenProcessError);
		}
		m_handle = UniqueHandle(hProcess);
	}

	explicit Process(const std::wstring& command, DWORD creationFlags = 0) {
		std::vector<wchar_t> buf(command.size() + 1);
		memcpy(buf.data(), command.c_str(), command.size() + 1);
		STARTUPINFOW startupInfo { sizeof(startupInfo) };
		PROCESS_INFORMATION processInformation { 0 };
		if (!CreateProcessW(NULL, buf.data(), NULL, NULL, NULL, creationFlags, NULL, NULL, &startupInfo, &processInformation)) {
			throw ProcessException(ProcessException::Type::kOpenProcessError);
		}
		m_handle = UniqueHandle(processInformation.hProcess);
		CloseHandle(processInformation.hThread);
	}

public:
	HANDLE Get() const noexcept {
		if (this == nullptr) {
			return (HANDLE)-1;
		}
		return m_handle.Get();
	}

	bool IsX86() const {
		auto handle = Get();
		if (handle == NULL) {
			throw ProcessException(ProcessException::Type::kProcessInvalid);
		}

		::BOOL IsWow64;
		if (!::IsWow64Process(handle, &IsWow64))
		{
			throw ProcessException(ProcessException::Type::kIsWow64ProcessError);
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

		throw ProcessException(ProcessException::Type::kIsWow64ProcessError);

	}


	// VirtualMemory
	std::vector<char> ReadMemory(void* addr, size_t len) {
		std::vector<char> buf(len);
		if (this == nullptr) {
			memcpy(buf.data(), addr, len);
			return buf;
		}
		SIZE_T readByte;
		if (!ReadProcessMemory(Get(), addr, buf.data(), len, &readByte)) {
			throw ProcessException(ProcessException::Type::kReadProcessMemoryError);
		}
		return buf;
	}

	void WriteMemory(void* addr, const void* buf, size_t len) {
		if (this == nullptr) {
			memcpy(addr, buf, len);
			return;
		}
		SIZE_T readByte;
		if (!WriteProcessMemory(Get(), addr, buf, len, &readByte)) {
			throw ProcessException(ProcessException::Type::kWriteProcessMemoryError);
		}
	}

	DWORD SetProtect(void* addr, size_t len, DWORD newProtect) {
		DWORD oldProtect;
		bool success = false;
		if (this == nullptr) {
			success = VirtualProtect(addr, len, newProtect, &oldProtect);
		}
		else {
			success = VirtualProtectEx(Get(), addr, len, newProtect, &oldProtect);
		}
		if (!success) {
			throw ProcessException(ProcessException::Type::kVirtualProtectError);
		}
		return oldProtect;
	}
private:
	UniqueHandle m_handle;
};

} // namespace geek

#endif // GEEK_PROCESS_H_
