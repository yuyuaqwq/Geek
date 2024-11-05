#pragma once
#include <memory>

#define _GEEK_IMPL				\
private:						\
	class Impl;					\
	std::unique_ptr<Impl> impl_;\

namespace geek {
enum class Arch {
	kX86,
	kX64,
};
}