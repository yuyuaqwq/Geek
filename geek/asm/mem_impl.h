#pragma once
#include <geek/asm/assembler_p.h>
#include <asmjit/asmjit.h>

namespace geek {
namespace internal {
class Mem::Impl {
public:
	Impl(asmjit::x86::Mem&& m);

	asmjit::x86::Mem mem_;
};
}
}