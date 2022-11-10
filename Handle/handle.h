#ifndef GEEK_HANDLE_H_
#define GEEK_HANDLE_H_

#include <Windows.h>

#include <type_traits>

namespace geek {

class UniqueHandle {
public:
	UniqueHandle() noexcept;
	explicit UniqueHandle(HANDLE t_handle) noexcept;
	~UniqueHandle() noexcept;

public:
	UniqueHandle(const UniqueHandle&) = delete;
	void operator=(const UniqueHandle&) = delete;

public:
	UniqueHandle(UniqueHandle&& t_uniqueHandle) noexcept;
	void operator=(UniqueHandle&& t_uniqueHandle) noexcept;

public:
	inline HANDLE Get() const noexcept;

	inline bool Valid() const noexcept;

private:
	inline void Close() noexcept;

private:
	HANDLE m_hanlde;
};

} // namespace geek

#endif // GEEK_HANDLE_H_
