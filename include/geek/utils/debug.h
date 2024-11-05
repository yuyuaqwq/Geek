#pragma once

#define _GEEK_CRT_WIDE_(s) L ## s
#define _GEEK_CRT_WIDE(s) _GEEK_CRT_WIDE_(s)

namespace geek {
void DebugOutput(const wchar_t* str) noexcept;
void AssertionFailed(const wchar_t* file, int line, const wchar_t* msg) noexcept;

#define GEEK_ASSERT_(cond, msg)                                        \
  do {                                                                 \
    if (!!(cond)) break;                                               \
    ::geek::AssertionFailed(_GEEK_CRT_WIDE(__FILE__), __LINE__, msg);  \
  } while (0)

#define GEEK_ASSERT(cond) GEEK_ASSERT_(cond, _GEEK_CRT_WIDE(#cond))

}