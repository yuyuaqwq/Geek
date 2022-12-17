#ifndef GEEK_HANDLE_HANDLE_H_
#define GEEK_HANDLE_HANDLE_H_

#include <Windows.h>

#include <type_traits>


namespace geek {

class UniqueHandle {
public:
	UniqueHandle() noexcept : mHanlde { (HANDLE)-1 } {

	}
	explicit UniqueHandle(HANDLE tHandle) noexcept : mHanlde{ tHandle } {

	}
	~UniqueHandle() noexcept {

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
		mHanlde = tUniqueHandle.mHanlde;
		tUniqueHandle.mHanlde = NULL;
	}

public:
	inline HANDLE Get() const noexcept {
		return mHanlde;
	}

	inline bool Valid() const noexcept {
		return mHanlde != NULL && mHanlde != INVALID_HANDLE_VALUE;
	}


private:
	inline void Close() noexcept {
		if (Valid()) {
			::CloseHandle(mHanlde);
		}
	}

private:
	HANDLE mHanlde;
};

} // namespace geek

#endif // GEEK_HANDLE_HANDLE_H_
