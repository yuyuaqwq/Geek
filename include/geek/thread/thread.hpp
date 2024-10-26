#ifndef GEEK_THREAD_THREAD_HPP_
#define GEEK_THREAD_THREAD_HPP_

#include <string>
#include <vector>
#include <optional>

#include <Windows.h>

#include <geek/handle.hpp>

namespace geek {
static const HANDLE kCurrentThread = (HANDLE)-2;

class Thread {
public:
    Thread(UniqueHandle thread_handle) : thread_handle_ { std::move(thread_handle) } {
        
    }

    static std::optional<Thread> Create(LPTHREAD_START_ROUTINE routine, LPVOID par = nullptr) {
        auto handle = ::CreateThread(NULL, 0, routine, par, 0, NULL);
        if (!handle) return {};
        return Thread{ handle };
    }

    static std::optional<Thread> Open(DWORD tid, DWORD desiredAccess = PROCESS_ALL_ACCESS) {
        auto handle = OpenThread(desiredAccess, FALSE, tid);
        if (!handle) return {};
        return Thread{ handle };
    }

    HANDLE Get() const noexcept {
        return thread_handle_.Get();
    }

    bool IsCur() const noexcept {
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
    UniqueHandle thread_handle_;
};


} // namespace geek

#endif // GEEK_THREAD_THREAD_HPP_
