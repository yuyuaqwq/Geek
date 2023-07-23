#ifndef GEEK_HANDLE_HANDLE_H_
#define GEEK_HANDLE_HANDLE_H_

#include <Windows.h>

#include <type_traits>


namespace geek {

class UniqueHandle {
public:
  UniqueHandle() noexcept : m_handle{ INVALID_HANDLE_VALUE } {

  }
  explicit UniqueHandle(HANDLE handle) noexcept : m_handle{ handle } {

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
    m_handle = tUniqueHandle.m_handle;
    tUniqueHandle.m_handle = INVALID_HANDLE_VALUE;
  }

public:
  inline HANDLE Get() const noexcept {
    return m_handle;
  }

  inline bool Valid() const noexcept {
    return m_handle != NULL && m_handle != INVALID_HANDLE_VALUE;
  }

  inline HANDLE Release() noexcept {
    auto temp = m_handle;
    m_handle = INVALID_HANDLE_VALUE;
    return temp;
  }

  inline void Reset(HANDLE handle = INVALID_HANDLE_VALUE) noexcept {
    Close();
    auto temp = m_handle;
    m_handle = handle;
  }

private:
  inline void Close() noexcept {
    if (Valid()) {
      ::CloseHandle(m_handle);
    }
  }

private:
  HANDLE m_handle;
};

} // namespace geek

#endif // GEEK_HANDLE_HANDLE_H_
