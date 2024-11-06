#pragma once
#include <geek/asm/assembler.h>

#include <asmjit/asmjit.h>
#include "assembler_p_impl.h"
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

Assembler::ErrorCode FromAsmJit(asmjit::ErrorCode code) noexcept;
asmjit::ErrorCode ToAsmJit(Assembler::ErrorCode code) noexcept;
asmjit::LabelType ToAsmJit(AsmLabelType type);

asmjit::Imm ToAsmJit(const internal::Imm& imm);
asmjit::x86::Mem ToAsmJit(const internal::Mem& mem);

const asmjit::x86::Reg& ToAsmJit(const internal::Reg& r);
const asmjit::x86::Gp& ToAsmJit(const internal::Gp& gp);
const asmjit::x86::Vec& ToAsmJit(const internal::Vec& gp);
const asmjit::x86::CReg& ToAsmJit(const internal::CReg& gp);
const asmjit::x86::DReg& ToAsmJit(const internal::DReg& gp);
const asmjit::x86::SReg& ToAsmJit(const internal::SReg& gp);
const asmjit::x86::Rip& ToAsmJit(const internal::Rip& gp);

const asmjit::Label& ToAsmJit(const internal::Label& label);
}
