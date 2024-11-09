#pragma once
#include <string>
#include <vector>
#include <optional>

#include <Windows.h>

#include <geek/utils/handle.h>

namespace geek {
static const HANDLE kCurrentThread = (HANDLE)-2;

class Thread {
public:
    Thread(UniqueHandle thread_handle);

    static std::optional<Thread> Create(LPTHREAD_START_ROUTINE routine, LPVOID par = nullptr);
    static std::optional<Thread> Open(DWORD tid, DWORD desiredAccess = PROCESS_ALL_ACCESS);
    HANDLE handle() const noexcept { return *thread_handle_; }

    bool IsCur() const noexcept;
    bool Suspend() const;
    bool Resume() const;
    bool WaitExit(DWORD dwMilliseconds = INFINITE) const;
    DWORD GetExitCode() const;

private:
    UniqueHandle thread_handle_;
};


} // namespace geek
