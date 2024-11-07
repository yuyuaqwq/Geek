#include "assembler_impl.h"

#include <cassert>

#include <mutex>

#include "asm/assembler/asm_op_defs_impl.h"
#include "utils/debug.h"

#define _GEEK_ASM_INST_MAKE_RET(e) \
	Error err{ FromAsmJit(static_cast<asmjit::ErrorCode>(e)) }; \
	if (impl_->config_.assert_every_inst) { \
		GEEK_ASSERT(err.IsSuccess(), "Assembler make instruction failed:", err.msg()); \
	} \
	return err; \

#define _GEEK_ASM_INST_0X_IMPL(op)								\
	_GEEK_ASM_INST_0X(Assembler::op) {							\
		_GEEK_ASM_INST_MAKE_RET(impl_->assembler_.op());		\
	}

#define _GEEK_ASM_INST_1X_IMPL(op, t0)								\
	_GEEK_ASM_INST_1X(Assembler::op, t0) {							\
		_GEEK_ASM_INST_MAKE_RET(impl_->assembler_.op(ToAsmJit(o0)));\
	}

#define _GEEK_ASM_INST_2X_IMPL(op, t0, t1)											\
	_GEEK_ASM_INST_2X(Assembler::op, t0, t1) {										\
		_GEEK_ASM_INST_MAKE_RET(impl_->assembler_.op(ToAsmJit(o0), ToAsmJit(o1)));	\
	}

#define _GEEK_ASM_INST_3X_IMPL(op, t0, t1, t2)													\
	_GEEK_ASM_INST_3X(Assembler::op, t0, t1, t2) {												\
		_GEEK_ASM_INST_MAKE_RET(impl_->assembler_.op(ToAsmJit(o0), ToAsmJit(o1), ToAsmJit(o2)));\
	}

namespace geek {
namespace {
asmjit::JitRuntime* Runtime() {
	static asmjit::JitRuntime inst;
	return &inst;
}
}
Assembler::~Assembler()
{
}

Assembler::Assembler(Arch arch)
{
	impl_ = std::make_unique<Impl>(this, arch, Runtime());
}

const AsmConfig& Assembler::Config() const {
	return impl_->config_;
}
AsmConfig& Assembler::Config() {
	return impl_->config_;
}

asm_op::Label Assembler::NewLabel() const
{
	asm_op::Label ret;
	ret.impl_ = std::make_unique<asm_op::Label::Impl>(impl_->assembler_.newLabel());
	return ret;
}

asm_op::Label Assembler::NewNamedLabel(std::string_view name, asm_op::Label::Type type) const
{
	asm_op::Label ret;
	ret.impl_ = std::make_unique<asm_op::Label::Impl>(impl_->assembler_.newNamedLabel(name.data(), name.size(), ToAsmJit(type)));
	return ret;
}

Assembler::Error Assembler::Bind(const asm_op::Label& label) const {
	auto e = impl_->assembler_.bind(ToAsmJit(label));
	return FromAsmJit(static_cast<asmjit::ErrorCode>(e));
}

std::vector<uint8_t> Assembler::PackCode() const
{
	auto size = impl_->code_.codeSize();
	auto data = impl_->code_.sectionById(0)->data();
	return { data, data + size };
}

Assembler::Error::Error(ErrorCode code)
	: code_(code)
{
}

std::string Assembler::Error::msg() const
{
	return asmjit::DebugUtils::errorAsString(ToAsmJit(code_));
}

bool Assembler::Error::IsSuccess() const {
	return code() == kErrorOk;
}

_GEEK_ASM_INST_2X_IMPL(adc, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(adc, Gp, Mem)
_GEEK_ASM_INST_2X_IMPL(adc, Gp, Imm)
_GEEK_ASM_INST_2X_IMPL(adc, Mem, Gp)
_GEEK_ASM_INST_2X_IMPL(adc, Mem, Imm)
_GEEK_ASM_INST_2X_IMPL(add, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(add, Gp, Mem)
_GEEK_ASM_INST_2X_IMPL(add, Gp, Imm)
_GEEK_ASM_INST_2X_IMPL(add, Mem, Gp)
_GEEK_ASM_INST_2X_IMPL(add, Mem, Imm)
_GEEK_ASM_INST_2X_IMPL(and_, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(and_, Gp, Mem)
_GEEK_ASM_INST_2X_IMPL(and_, Gp, Imm)
_GEEK_ASM_INST_2X_IMPL(and_, Mem, Gp)
_GEEK_ASM_INST_2X_IMPL(and_, Mem, Imm)
_GEEK_ASM_INST_2X_IMPL(bound, Gp, Mem)
_GEEK_ASM_INST_2X_IMPL(bsf, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(bsf, Gp, Mem)
_GEEK_ASM_INST_2X_IMPL(bsr, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(bsr, Gp, Mem)
_GEEK_ASM_INST_1X_IMPL(bswap, Gp)
_GEEK_ASM_INST_2X_IMPL(bt, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(bt, Gp, Imm)
_GEEK_ASM_INST_2X_IMPL(bt, Mem, Gp)
_GEEK_ASM_INST_2X_IMPL(bt, Mem, Imm)
_GEEK_ASM_INST_2X_IMPL(btc, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(btc, Gp, Imm)
_GEEK_ASM_INST_2X_IMPL(btc, Mem, Gp)
_GEEK_ASM_INST_2X_IMPL(btc, Mem, Imm)
_GEEK_ASM_INST_2X_IMPL(btr, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(btr, Gp, Imm)
_GEEK_ASM_INST_2X_IMPL(btr, Mem, Gp)
_GEEK_ASM_INST_2X_IMPL(btr, Mem, Imm)
_GEEK_ASM_INST_2X_IMPL(bts, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(bts, Gp, Imm)
_GEEK_ASM_INST_2X_IMPL(bts, Mem, Gp)
_GEEK_ASM_INST_2X_IMPL(bts, Mem, Imm)
_GEEK_ASM_INST_1X_IMPL(cbw, Gp_AX)
_GEEK_ASM_INST_2X_IMPL(cdq, Gp_EDX, Gp_EAX)
_GEEK_ASM_INST_1X_IMPL(cdqe, Gp_EAX)
_GEEK_ASM_INST_2X_IMPL(cqo, Gp_RDX, Gp_RAX)
_GEEK_ASM_INST_2X_IMPL(cwd, Gp_DX, Gp_AX)
_GEEK_ASM_INST_1X_IMPL(cwde, Gp_EAX)
_GEEK_ASM_INST_1X_IMPL(call, Gp)
_GEEK_ASM_INST_1X_IMPL(call, Mem)
_GEEK_ASM_INST_1X_IMPL(call, Label)
_GEEK_ASM_INST_1X_IMPL(call, Imm)

_GEEK_ASM_INST_2X_IMPL(cmp, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(cmp, Gp, Mem)
_GEEK_ASM_INST_2X_IMPL(cmp, Gp, Imm)
_GEEK_ASM_INST_2X_IMPL(cmp, Mem, Gp)
_GEEK_ASM_INST_2X_IMPL(cmp, Mem, Imm)
_GEEK_ASM_INST_2X_IMPL(cmps, DS_ZSI, ES_ZDI)

_GEEK_ASM_INST_1X_IMPL(dec, Gp)
_GEEK_ASM_INST_1X_IMPL(dec, Mem)
_GEEK_ASM_INST_2X_IMPL(div, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(div, Gp, Mem)
_GEEK_ASM_INST_3X_IMPL(div, Gp, Gp, Gp)
_GEEK_ASM_INST_3X_IMPL(div, Gp, Gp, Mem)
_GEEK_ASM_INST_2X_IMPL(idiv, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(idiv, Gp, Mem)
_GEEK_ASM_INST_3X_IMPL(idiv, Gp, Gp, Gp)
_GEEK_ASM_INST_3X_IMPL(idiv, Gp, Gp, Mem)
_GEEK_ASM_INST_2X_IMPL(imul, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(imul, Gp, Mem)
_GEEK_ASM_INST_3X_IMPL(imul, Gp, Gp, Imm)
_GEEK_ASM_INST_3X_IMPL(imul, Gp, Mem, Imm)
_GEEK_ASM_INST_3X_IMPL(imul, Gp, Gp, Gp)
_GEEK_ASM_INST_3X_IMPL(imul, Gp, Gp, Mem)
_GEEK_ASM_INST_1X_IMPL(inc, Gp)
_GEEK_ASM_INST_1X_IMPL(inc, Mem)
_GEEK_ASM_INST_2X_IMPL(jecxz, Gp, Label)
_GEEK_ASM_INST_2X_IMPL(jecxz, Gp, Imm)
_GEEK_ASM_INST_1X_IMPL(jmp, Gp)
_GEEK_ASM_INST_1X_IMPL(jmp, Mem)
_GEEK_ASM_INST_1X_IMPL(jmp, Label)
_GEEK_ASM_INST_1X_IMPL(jmp, Imm)
_GEEK_ASM_INST_2X_IMPL(lcall, Imm, Imm)
_GEEK_ASM_INST_1X_IMPL(lcall, Mem)
_GEEK_ASM_INST_2X_IMPL(lea, Gp, Mem)
_GEEK_ASM_INST_2X_IMPL(ljmp, Imm, Imm)
_GEEK_ASM_INST_1X_IMPL(ljmp, Mem)
_GEEK_ASM_INST_2X_IMPL(lods, Gp_ZAX, DS_ZSI)
_GEEK_ASM_INST_2X_IMPL(loop, Gp_ZCX, Label)
_GEEK_ASM_INST_2X_IMPL(loop, Gp_ZCX, Imm)
_GEEK_ASM_INST_2X_IMPL(loope, Gp_ZCX, Label)
_GEEK_ASM_INST_2X_IMPL(loope, Gp_ZCX, Imm)
_GEEK_ASM_INST_2X_IMPL(loopne, Gp_ZCX, Label)
_GEEK_ASM_INST_2X_IMPL(loopne, Gp_ZCX, Imm)
_GEEK_ASM_INST_2X_IMPL(mov, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(mov, Gp, Mem)
_GEEK_ASM_INST_2X_IMPL(mov, Gp, Imm)
_GEEK_ASM_INST_2X_IMPL(mov, Mem, Gp)
_GEEK_ASM_INST_2X_IMPL(mov, Mem, Imm)
_GEEK_ASM_INST_2X_IMPL(mov, Gp, CReg)
_GEEK_ASM_INST_2X_IMPL(mov, CReg, Gp)
_GEEK_ASM_INST_2X_IMPL(mov, Gp, DReg)
_GEEK_ASM_INST_2X_IMPL(mov, DReg, Gp)
_GEEK_ASM_INST_2X_IMPL(mov, Gp, SReg)
_GEEK_ASM_INST_2X_IMPL(mov, Mem, SReg)
_GEEK_ASM_INST_2X_IMPL(mov, SReg, Gp)
_GEEK_ASM_INST_2X_IMPL(mov, SReg, Mem)
_GEEK_ASM_INST_2X_IMPL(movabs, Gp, Mem)
_GEEK_ASM_INST_2X_IMPL(movabs, Gp, Imm)
_GEEK_ASM_INST_2X_IMPL(movabs, Mem, Gp)

_GEEK_ASM_INST_2X_IMPL(movs, ES_ZDI, DS_ZSI)
_GEEK_ASM_INST_2X_IMPL(movsx, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(movsx, Gp, Mem)
_GEEK_ASM_INST_2X_IMPL(movsxd, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(movsxd, Gp, Mem)
_GEEK_ASM_INST_2X_IMPL(movzx, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(movzx, Gp, Mem)
_GEEK_ASM_INST_2X_IMPL(mul, Gp_AX, Gp)
_GEEK_ASM_INST_2X_IMPL(mul, Gp_AX, Mem)
_GEEK_ASM_INST_3X_IMPL(mul, Gp_ZDX, Gp_ZAX, Gp)
_GEEK_ASM_INST_3X_IMPL(mul, Gp_ZDX, Gp_ZAX, Mem)
_GEEK_ASM_INST_1X_IMPL(neg, Gp)
_GEEK_ASM_INST_1X_IMPL(neg, Mem)
_GEEK_ASM_INST_0X_IMPL(nop)
_GEEK_ASM_INST_1X_IMPL(nop, Gp)
_GEEK_ASM_INST_1X_IMPL(nop, Mem)
_GEEK_ASM_INST_2X_IMPL(nop, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(nop, Mem, Gp)
_GEEK_ASM_INST_1X_IMPL(not_, Gp)
_GEEK_ASM_INST_1X_IMPL(not_, Mem)
_GEEK_ASM_INST_2X_IMPL(or_, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(or_, Gp, Mem)
_GEEK_ASM_INST_2X_IMPL(or_, Gp, Imm)
_GEEK_ASM_INST_2X_IMPL(or_, Mem, Gp)
_GEEK_ASM_INST_2X_IMPL(or_, Mem, Imm)
_GEEK_ASM_INST_1X_IMPL(pop, Gp)
_GEEK_ASM_INST_1X_IMPL(pop, Mem)
_GEEK_ASM_INST_1X_IMPL(pop, SReg)
_GEEK_ASM_INST_0X_IMPL(popa)
_GEEK_ASM_INST_0X_IMPL(popad)
_GEEK_ASM_INST_0X_IMPL(popf)
_GEEK_ASM_INST_0X_IMPL(popfd)
_GEEK_ASM_INST_0X_IMPL(popfq)
_GEEK_ASM_INST_1X_IMPL(push, Gp)
_GEEK_ASM_INST_1X_IMPL(push, Mem)
_GEEK_ASM_INST_1X_IMPL(push, SReg)
_GEEK_ASM_INST_1X_IMPL(push, Imm)
_GEEK_ASM_INST_0X_IMPL(pusha)
_GEEK_ASM_INST_0X_IMPL(pushad)
_GEEK_ASM_INST_0X_IMPL(pushf)
_GEEK_ASM_INST_0X_IMPL(pushfd)
_GEEK_ASM_INST_0X_IMPL(pushfq)
_GEEK_ASM_INST_2X_IMPL(rcl, Gp, Gp_CL)
_GEEK_ASM_INST_2X_IMPL(rcl, Mem, Gp_CL)
_GEEK_ASM_INST_2X_IMPL(rcl, Gp, Imm)
_GEEK_ASM_INST_2X_IMPL(rcl, Mem, Imm)
_GEEK_ASM_INST_2X_IMPL(rcr, Gp, Gp_CL)
_GEEK_ASM_INST_2X_IMPL(rcr, Mem, Gp_CL)
_GEEK_ASM_INST_2X_IMPL(rcr, Gp, Imm)
_GEEK_ASM_INST_2X_IMPL(rcr, Mem, Imm)
_GEEK_ASM_INST_2X_IMPL(rol, Gp, Gp_CL)
_GEEK_ASM_INST_2X_IMPL(rol, Mem, Gp_CL)
_GEEK_ASM_INST_2X_IMPL(rol, Gp, Imm)
_GEEK_ASM_INST_2X_IMPL(rol, Mem, Imm)
_GEEK_ASM_INST_2X_IMPL(ror, Gp, Gp_CL)
_GEEK_ASM_INST_2X_IMPL(ror, Mem, Gp_CL)
_GEEK_ASM_INST_2X_IMPL(ror, Gp, Imm)
_GEEK_ASM_INST_2X_IMPL(ror, Mem, Imm)
_GEEK_ASM_INST_2X_IMPL(sbb, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(sbb, Gp, Mem)
_GEEK_ASM_INST_2X_IMPL(sbb, Gp, Imm)
_GEEK_ASM_INST_2X_IMPL(sbb, Mem, Gp)
_GEEK_ASM_INST_2X_IMPL(sbb, Mem, Imm)
_GEEK_ASM_INST_2X_IMPL(sal, Gp, Gp_CL)
_GEEK_ASM_INST_2X_IMPL(sal, Mem, Gp_CL)
_GEEK_ASM_INST_2X_IMPL(sal, Gp, Imm)
_GEEK_ASM_INST_2X_IMPL(sal, Mem, Imm)
_GEEK_ASM_INST_2X_IMPL(sar, Gp, Gp_CL)
_GEEK_ASM_INST_2X_IMPL(sar, Mem, Gp_CL)
_GEEK_ASM_INST_2X_IMPL(sar, Gp, Imm)
_GEEK_ASM_INST_2X_IMPL(sar, Mem, Imm)
_GEEK_ASM_INST_2X_IMPL(scas, Gp_ZAX, ES_ZDI)
_GEEK_ASM_INST_2X_IMPL(shl, Gp, Gp_CL)
_GEEK_ASM_INST_2X_IMPL(shl, Mem, Gp_CL)
_GEEK_ASM_INST_2X_IMPL(shl, Gp, Imm)
_GEEK_ASM_INST_2X_IMPL(shl, Mem, Imm)
_GEEK_ASM_INST_2X_IMPL(shr, Gp, Gp_CL)
_GEEK_ASM_INST_2X_IMPL(shr, Mem, Gp_CL)
_GEEK_ASM_INST_2X_IMPL(shr, Gp, Imm)
_GEEK_ASM_INST_2X_IMPL(shr, Mem, Imm)
_GEEK_ASM_INST_3X_IMPL(shld, Gp, Gp, Gp_CL)
_GEEK_ASM_INST_3X_IMPL(shld, Mem, Gp, Gp_CL)
_GEEK_ASM_INST_3X_IMPL(shld, Gp, Gp, Imm)
_GEEK_ASM_INST_3X_IMPL(shld, Mem, Gp, Imm)
_GEEK_ASM_INST_3X_IMPL(shrd, Gp, Gp, Gp_CL)
_GEEK_ASM_INST_3X_IMPL(shrd, Mem, Gp, Gp_CL)
_GEEK_ASM_INST_3X_IMPL(shrd, Gp, Gp, Imm)
_GEEK_ASM_INST_3X_IMPL(shrd, Mem, Gp, Imm)
_GEEK_ASM_INST_2X_IMPL(stos, ES_ZDI, Gp_ZAX)
_GEEK_ASM_INST_2X_IMPL(sub, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(sub, Gp, Mem)
_GEEK_ASM_INST_2X_IMPL(sub, Gp, Imm)
_GEEK_ASM_INST_2X_IMPL(sub, Mem, Gp)
_GEEK_ASM_INST_2X_IMPL(sub, Mem, Imm)
_GEEK_ASM_INST_2X_IMPL(test, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(test, Gp, Imm)
_GEEK_ASM_INST_2X_IMPL(test, Mem, Gp)
_GEEK_ASM_INST_2X_IMPL(test, Mem, Imm)
_GEEK_ASM_INST_2X_IMPL(ud0, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(ud0, Gp, Mem)
_GEEK_ASM_INST_2X_IMPL(ud1, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(ud1, Gp, Mem)
_GEEK_ASM_INST_0X_IMPL(ud2)
_GEEK_ASM_INST_2X_IMPL(xadd, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(xadd, Mem, Gp)
_GEEK_ASM_INST_2X_IMPL(xchg, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(xchg, Mem, Gp)
_GEEK_ASM_INST_2X_IMPL(xchg, Gp, Mem)
_GEEK_ASM_INST_2X_IMPL(xor_, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(xor_, Gp, Mem)
_GEEK_ASM_INST_2X_IMPL(xor_, Gp, Imm)
_GEEK_ASM_INST_2X_IMPL(xor_, Mem, Gp)
_GEEK_ASM_INST_2X_IMPL(xor_, Mem, Imm)

//! \name Deprecated 32-bit Instructions
//! \{

_GEEK_ASM_INST_1X_IMPL(aaa, Gp)
_GEEK_ASM_INST_2X_IMPL(aad, Gp, Imm)
_GEEK_ASM_INST_2X_IMPL(aam, Gp, Imm)
_GEEK_ASM_INST_1X_IMPL(aas, Gp)
_GEEK_ASM_INST_1X_IMPL(daa, Gp)
_GEEK_ASM_INST_1X_IMPL(das, Gp)

//! \name ENTER/LEAVE Instructions
//! \{

_GEEK_ASM_INST_2X_IMPL(enter, Imm, Imm)
_GEEK_ASM_INST_0X_IMPL(leave)

//! \name IN/OUT Instructions
//! \{

// NOTE: For some reason Doxygen is messed up here and thinks we are in cond.

_GEEK_ASM_INST_2X_IMPL(in, Gp_ZAX, Imm)
_GEEK_ASM_INST_2X_IMPL(in, Gp_ZAX, Gp_DX)
_GEEK_ASM_INST_2X_IMPL(ins, ES_ZDI, Gp_DX)
_GEEK_ASM_INST_2X_IMPL(out, Imm, Gp_ZAX)
_GEEK_ASM_INST_2X_IMPL(out, Gp_DX, Gp_ZAX)
_GEEK_ASM_INST_2X_IMPL(outs, Gp_DX, DS_ZSI)

//! \name Clear/Set CF/DF Instructions
//! \{

_GEEK_ASM_INST_0X_IMPL(clc)
_GEEK_ASM_INST_0X_IMPL(cld)
_GEEK_ASM_INST_0X_IMPL(cmc)
_GEEK_ASM_INST_0X_IMPL(stc)
_GEEK_ASM_INST_0X_IMPL(std)
}
