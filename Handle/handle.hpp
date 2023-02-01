#ifndef GEEK_HANDLE_HANDLE_H_
#define GEEK_HANDLE_HANDLE_H_

#include <Windows.h>

#include <type_traits>


namespace geek {

class UniqueHandle {
public:
	UniqueHandle() noexcept : mHandle{ INVALID_HANDLE_VALUE } {

	}
	explicit UniqueHandle(HANDLE tHandle) noexcept : mHandle{ tHandle } {

	}
	~UniqueHandle() noexcept {
		Close();
	}

public:
	UniqueHandle(const UniqueHandle&) = delete;
	void operator=(const UniqueHandle&) = delete;

public:
	UniqueHandle(UniqueHandle&& tUniqueHandle) noexcept {
		*this = std::move(tUniqueHandle);
	}
	void operator=(UniqueHandle&& tUniqueHandle) noexcept {
		Close();
		mHandle = tUniqueHandle.mHandle;
		tUniqueHandle.mHandle = INVALID_HANDLE_VALUE;
	}

public:
	inline HANDLE Get() const noexcept {
		return mHandle;
	}

	inline bool Valid() const noexcept {
		return mHandle != NULL && mHandle != INVALID_HANDLE_VALUE;
	}

	inline HANDLE Release() noexcept {
		auto temp = mHandle;
		mHandle = INVALID_HANDLE_VALUE;
		return temp;
	}

	inline void Reset(HANDLE handle = INVALID_HANDLE_VALUE) noexcept {
		Close();
		auto temp = mHandle;
		mHandle = handle;
	}

private:
	inline void Close() noexcept {
		if (Valid()) {
			::CloseHandle(mHandle);
		}
	}

private:
	HANDLE mHandle;
};

} // namespace geek

#endif // GEEK_HANDLE_HANDLE_H_
