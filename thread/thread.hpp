#ifndef GEEK_THREAD_THREAD_H_
#define GEEK_THREAD_THREAD_H_

#include <string>
#include <vector>

#include <Windows.h>

#include <geek/handle.hpp>

namespace Geek {
static const HANDLE kCurrentThread = (HANDLE)-2;


class Thread {
public:
    Thread() {
        Open(UniqueHandle(kCurrentThread));
    }

    void Create(LPTHREAD_START_ROUTINE routine, LPVOID par = nullptr) {
        m_handle.Reset(::CreateThread(NULL, 0, routine, par, 0, NULL));
    }

    void Open(UniqueHandle hThread) {
        m_handle = std::move(hThread);
    }

    bool Open(DWORD tid, DWORD desiredAccess = PROCESS_ALL_ACCESS) {
        auto hThread = OpenThread(desiredAccess, FALSE, tid);
        if (hThread == NULL) {
            return false;
        }
        m_handle = UniqueHandle(hThread);
        return true;
    }

    bool IsVaild() {
        if (this == nullptr) { return true; }
        return m_handle.IsValid();
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


    bool Suspend() {
        return ::SuspendThread(Get());
    }

    bool Resume() {
        return ::ResumeThread(Get());
    }

    bool WaitExit(DWORD dwMilliseconds = INFINITE) {
        if (IsCur()) {
            return false;
        }
        return WaitForSingleObject(Get(), dwMilliseconds) == WAIT_OBJECT_0;
    }

    DWORD GetExitCode() {
        DWORD code;
        if (!::GetExitCodeThread(Get(), &code)) {
            return 0;
        }
        return code;
    }
    

private:
    UniqueHandle m_handle;


};


} // namespace Geek

#endif // GEEK_THREAD_THREAD_H_
