#include "debug.h"

#include <Windows.h>

namespace geek {
void DebugOutput(std::string_view str) noexcept
{
	::OutputDebugStringA(str.data());
}

void AssertionFailed(std::string_view file, int line, std::string_view msg) noexcept
{
    DebugOutput(StrUtil::Combine("[Geek] Assertion failed at ", file, " (line ", line, "):", msg));
    ::abort();
}

void WDebugOutput(std::wstring_view str) noexcept
{
	::OutputDebugStringW(str.data());
}

void WAssertionFailed(std::wstring_view file, int line, std::wstring_view msg) noexcept
{
    WDebugOutput(StrUtil::WCombine(L"[Geek] Assertion failed at ", file, L" (line ", line, L"):", msg));
    ::abort();
}

std::string internal::MsgOfThrow(std::string_view file, int line, std::string_view msg) noexcept
{
	return StrUtil::Combine("[Geek] Exception at ", file, " (line ", line, "):", msg);
}

std::wstring internal::WMsgOfThrow(std::wstring_view file, int line, std::wstring_view msg) noexcept
{
	return StrUtil::WCombine(L"[Geek] Exception at ", file, L" (line ", line, L"):", msg);
}
}
