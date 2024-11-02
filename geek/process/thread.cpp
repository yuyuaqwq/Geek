#include <geek/process/thread.h>

namespace geek {
Thread::Thread(UniqueHandle thread_handle)
	: thread_handle_ { std::move(thread_handle) }
{
}

std::optional<Thread> Thread::Create(LPTHREAD_START_ROUTINE routine, LPVOID par)
{
	auto handle = ::CreateThread(NULL, 0, routine, par, 0, NULL);
	if (!handle) return {};
	return Thread{ handle };
}

std::optional<Thread> Thread::Open(DWORD tid, DWORD desiredAccess)
{
	auto handle = OpenThread(desiredAccess, FALSE, tid);
	if (!handle) return {};
	return Thread{ handle };
}

bool Thread::IsCur() const noexcept
{
	return *thread_handle_ == kCurrentThread;
}

bool Thread::Suspend() const
{
	return ::SuspendThread(*thread_handle_);
}

bool Thread::Resume() const
{
	return ::ResumeThread(*thread_handle_);
}

bool Thread::WaitExit(DWORD dwMilliseconds) const
{
	if (IsCur()) {
		return false;
	}
	return WaitForSingleObject(*thread_handle_, dwMilliseconds) == WAIT_OBJECT_0;
}

DWORD Thread::GetExitCode() const
{
	DWORD code;
	if (!::GetExitCodeThread(*thread_handle_, &code)) {
		return 0;
	}
	return code;
}
}
