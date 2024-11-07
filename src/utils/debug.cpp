#include "debug.h"

#include <iostream>
#include <Windows.h>

namespace geek {
void DebugOutput(std::string_view str) noexcept {
	std::cout << str.data() << std::endl;
	::OutputDebugStringA(str.data());
}

void WDebugOutput(std::wstring_view str) noexcept {
	std::wcout << str.data() << std::endl;
	::OutputDebugStringW(str.data());
}

namespace internal {
void AssertionFailed(std::string_view file, int line, std::string_view msg) noexcept {
	DebugOutput(StrUtil::Combine("[Geek] Assertion failed at ", file, " (line ", line, "):", msg));
	::abort();
}

void AssertionFailed(std::string_view file, std::string_view func, int line, std::string_view msg) noexcept {
	DebugOutput(StrUtil::Combine("[Geek] Assertion failed at ", file, " (func ", func, ") (line ", line, "):", msg));
	::abort();
}

void WAssertionFailed(std::wstring_view file, int line, std::wstring_view msg) noexcept {
	WDebugOutput(StrUtil::WCombine(L"[Geek] Assertion failed at ", file, L" (line ", line, L"):", msg));
	::abort();
}

void WAssertionFailed(std::wstring_view file, std::wstring_view func, int line, std::wstring_view msg) noexcept {
	WDebugOutput(StrUtil::WCombine(L"[Geek] Assertion failed at ", file, L" (func ", func, L") (line ", line, L"):", msg));
	::abort();
}

std::string MsgOfThrow(std::string_view file, int line, std::string_view msg) noexcept {
	return StrUtil::Combine("[Geek] Exception at ", file, " (line ", line, "):", msg);
}

std::string MsgOfThrow(std::string_view file, std::string_view func, int line, std::string_view msg) noexcept {
	return StrUtil::Combine("[Geek] Exception at ", file, L" (func ", func, ") (line ", line, "):", msg);
}

std::wstring WMsgOfThrow(std::wstring_view file, int line, std::wstring_view msg) noexcept {
	return StrUtil::WCombine(L"[Geek] Exception at ", file, L" (line ", line, L"):", msg);
}

std::wstring WMsgOfThrow(std::wstring_view file, std::wstring_view func, int line, std::wstring_view msg) noexcept {
	return StrUtil::WCombine(L"[Geek] Exception at ", file, L" (func ", func, L") (line ", line, L"):", msg);
}
}
}
