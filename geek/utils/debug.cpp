#include <geek/utils/debug.h>

#include <Windows.h>
#include <sstream>

namespace geek {
void DebugOutput(const wchar_t* str) noexcept
{
#if defined(_WIN32)
	::OutputDebugStringW(str);
#else
	::fputs(str, stderr);
#endif
}

void AssertionFailed(const wchar_t* file, int line, const wchar_t* msg) noexcept
{
    std::wstringstream wss;
    wss << L"[geek] Assertion failed at" << file << L"(line " << line << "): " << msg;
    DebugOutput(wss.str().c_str());
    ::abort();
}
}