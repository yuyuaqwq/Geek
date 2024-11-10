#pragma once
#include <memory>

#define _GEEK_IMPL_				\
	class Impl;					\
	std::unique_ptr<Impl> impl_;\

#define _GEEK_IMPL private: _GEEK_IMPL_

#define _GEEK_PUB_IMPL public: _GEEK_IMPL_

#if !defined(GEEK_BUILD_DEBUG) && !defined(GEEK_BUILD_RELEASE)
#if !defined(NDEBUG)
#define GEEK_BUILD_DEBUG
#else
#define GEEK_BUILD_RELEASE
#endif
#endif

namespace geek {
enum class Arch : uint8_t {
	kX86,
	kX64,
};
}