#include <geek/utils/debug.h>
#include <Windows.h>

namespace geek {
void DebugOutput(std::string_view str) noexcept
{
#if defined(_WIN32)
	::OutputDebugStringA(str.data());
#else
	::fputs(str, stderr);
#endif
}

void AssertionFailed(std::string_view file, int line, std::string_view msg) noexcept
{
    DebugOutput(StrUtil::Combine("[Geek] Assertion failed at ", file, " (line ", line, "):", msg));
    ::abort();
}

std::string internal::MsgOfThrow(std::string_view file, int line, std::string_view msg) noexcept
{
	return StrUtil::Combine("[Geek] Exception at ", file, " (line ", line, "):", msg);
}
}
