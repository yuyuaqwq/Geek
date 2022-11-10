#ifndef GEEK_PROCESS_H_
#define GEEK_PROCESS_H_

#include <exception>
#include <string>
#include <vector>

#include <Handle/handle.h>

namespace geek {
	
class ProcessExceptionType {

};

class ProcessException : public std::exception {
public:
	enum class Type {
		kProcessInvalid,
		kOpenProcessError,
		kCreateProcessError,
		kIsWow64ProcessError,
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
	Process(DWORD pid, DWORD desiredAccess = PROCESS_ALL_ACCESS) {
		auto hProcess = OpenProcess(desiredAccess, FALSE, pid);
		if (hProcess == NULL) {
			throw ProcessException(ProcessException::Type::kOpenProcessError);
		}
		m_handle = UniqueHandle(hProcess);
	}

	Process(const std::wstring& command, DWORD creationFlags = 0) {
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
	bool IsX86() const {
		if (m_handle.Get() == NULL) {
			throw ProcessException(ProcessException::Type::kProcessInvalid);
		}

		::BOOL IsWow64;
		if (!::IsWow64Process(m_handle.Get(), &IsWow64))
		{
			throw ProcessException(ProcessException::Type::kIsWow64ProcessError);
		}

		if (IsWow64)
		{
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

private:
	UniqueHandle m_handle;
};

} // namespace geek

#endif // GEEK_PROCESS_H_
