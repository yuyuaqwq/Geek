#include <geek/utils/handle.h>
#include <algorithm>

namespace geek {
UniqueHandle::UniqueHandle() noexcept
	: handle_{INVALID_HANDLE_VALUE}
{
}

UniqueHandle::UniqueHandle(HANDLE handle) noexcept
	: handle_{ handle }
{
}

UniqueHandle::~UniqueHandle() noexcept
{
	Reset();
}

UniqueHandle::UniqueHandle(UniqueHandle&& right) noexcept
{
	handle_ = INVALID_HANDLE_VALUE;
	*this = std::move(right);
}

UniqueHandle& UniqueHandle::operator=(UniqueHandle&& right) noexcept
{
	Reset();
	handle_ = right.handle_;
	right.handle_ = INVALID_HANDLE_VALUE;
	return *this;
}

bool UniqueHandle::IsValid() const noexcept
{
	return handle_ != NULL && handle_ != INVALID_HANDLE_VALUE;
}

HANDLE UniqueHandle::Release() noexcept
{
	auto temp = handle_;
	handle_ = INVALID_HANDLE_VALUE;
	return temp;
}

void UniqueHandle::Reset(HANDLE handle) noexcept
{
	if (IsValid()) {
		::CloseHandle(handle_);
	}
	handle_ = handle;
}
}
