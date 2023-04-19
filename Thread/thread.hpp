#ifndef GEEK_THREAD_THREAD_H_
#define GEEK_THREAD_THREAD_H_

#include <string>
#include <vector>

#include <Windows.h>

#include <Geek\Handle\handle.hpp>

namespace Geek {
static const HANDLE kCurrentThread = (HANDLE)-2;


class Thread {
public:
	Thread() {
		Open(UniqueHandle(kCurrentThread));
	}

	void Open(UniqueHandle hThread) {
		m_handle = std::move(hThread);
	}

	bool Open(DWORD tid, DWORD desiredAccess = PROCESS_ALL_ACCESS) {
		auto hThread = OpenProcess(desiredAccess, FALSE, tid);
		if (hThread == NULL) {
			return false;
		}
		m_handle = UniqueHandle(hThread);
		return true;
	}

	HANDLE Get() const noexcept {
		if (this == nullptr) {
			return kCurrentThread;
		}
		return m_handle.Get();
	}

	bool IsCur() {
		return Get() == kCurrentThread;
	}


	bool SuspendThread() {
		return ::SuspendThread(Get());
	}

	bool ResumeThread() {
		return ::ResumeThread(Get());
	}

	

private:
	UniqueHandle m_handle;
};


} // namespace Geek

#endif // GEEK_THREAD_THREAD_H_
