#pragma once
#include <geek/asm/assembler.h>
#include <asmjit/asmjit.h>

#include <geek/utils/debug.h>

namespace geek {
class Assembler::Impl
{
public:
	Impl(Assembler* owner, Arch arch, asmjit::JitRuntime* runtime);

	Assembler* owner_;
	asmjit::JitRuntime* runtime_;
	asmjit::CodeHolder code_;
	asmjit::x86::Assembler assembler_;
};

struct RegDeleter {
	RegDeleter() noexcept = default;

	void operator()(void* ptr) const noexcept {
		deleter(ptr);
	}

	void(*deleter)(void* ptr);
};

std::unique_ptr<asmjit::x86::Reg, RegDeleter> ToAsmJit(regs r);

Assembler::ErrorCode FromAsmJit(asmjit::ErrorCode code) noexcept;
asmjit::ErrorCode ToAsmJit(Assembler::ErrorCode code) noexcept;

asmjit::Imm ToAsmJit(const internal::Imm& imm);
asmjit::x86::Mem ToAsmJit(const internal::Mem& mem);

#define TO_ASMJIT_REG(x) std::unique_ptr<asmjit::x86::x, RegDeleter> ToAsmJit##x(regs r);

TO_ASMJIT_REG(Gp)
TO_ASMJIT_REG(Vec)
TO_ASMJIT_REG(Rip)
}
