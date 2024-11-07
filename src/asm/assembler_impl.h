#pragma once
#include <geek/asm/assembler.h>

#include <asmjit/asmjit.h>
#include <geek/asm/assembler/asm_op_defs.h>


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
asmjit::LabelType ToAsmJit(asm_op::Label::Type type);

asmjit::Imm ToAsmJit(const asm_op::Imm& imm);
asmjit::x86::Mem ToAsmJit(const asm_op::Mem& mem);

const asmjit::x86::Reg& ToAsmJit(const asm_op::Reg& r);
const asmjit::x86::Gp& ToAsmJit(const asm_op::Gp& gp);
const asmjit::x86::Vec& ToAsmJit(const asm_op::Vec& gp);
const asmjit::x86::CReg& ToAsmJit(const asm_op::CReg& gp);
const asmjit::x86::DReg& ToAsmJit(const asm_op::DReg& gp);
const asmjit::x86::SReg& ToAsmJit(const asm_op::SReg& gp);
const asmjit::x86::Rip& ToAsmJit(const asm_op::Rip& gp);

const asmjit::Label& ToAsmJit(const asm_op::Label& label);
}
