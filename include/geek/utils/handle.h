#ifndef GEEK_HANDLE_HANDLE_H_
#define GEEK_HANDLE_HANDLE_H_

#include <Windows.h>

namespace geek {

class UniqueHandle {
public:
    UniqueHandle() noexcept;

    UniqueHandle(HANDLE handle) noexcept;

    ~UniqueHandle() noexcept;

    UniqueHandle(const UniqueHandle&) = delete;
    void operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& right) noexcept;
    UniqueHandle& operator=(UniqueHandle&& right) noexcept;

    HANDLE operator*() const noexcept { return handle_; }
    operator bool() const { return IsValid(); }

    bool IsValid() const noexcept;
    HANDLE Release() noexcept;

    void Reset(HANDLE handle = INVALID_HANDLE_VALUE) noexcept;

private:
    HANDLE handle_;
};

} // namespace geek

#endif // GEEK_HANDLE_HANDLE_H_
