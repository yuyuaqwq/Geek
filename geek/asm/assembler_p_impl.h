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
class Label::Impl {
public:
	Impl(asmjit::Label&& m);

	asmjit::Label label_;
};

class Reg::Impl {
public:
	Impl(RegisterId id);

	std::unique_ptr<asmjit::x86::Reg> reg_;
};
}
}