#pragma once
#include <geek/utils/strutil.h>

namespace geek {
void DebugOutput(std::string_view str) noexcept;
void AssertionFailed(std::string_view file, int line, std::string_view msg) noexcept;

namespace internal {
std::string MsgOfThrow(std::string_view file, int line, std::string_view msg) noexcept;
}
}

#define GEEK_ASSERT_(cond, msg)								\
	do {													\
		if (!!(cond)) break;								\
			geek::AssertionFailed(__FILE__, __LINE__, msg); \
	} while (0)

#define GEEK_ASSERT_X(cond)		GEEK_ASSERT_(cond, #cond)
#define GEEK_ASSERT(cond, ...)	GEEK_ASSERT_(cond, geek::StrUtil::Combine(__VA_ARGS__))

#define GEEK_THROW(...)			throw std::exception(geek::internal::MsgOfThrow(__FILE__, __LINE__, geek::StrUtil::Combine(__VA_ARGS__)).c_str())