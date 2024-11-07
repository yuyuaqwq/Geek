#pragma once
#include <geek/asm/assembler/asm_op_defs.h>
#include <asmjit/asmjit.h>

namespace geek {
namespace asm_op {
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