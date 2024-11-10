#include "assembler_impl.h"

#include <mutex>

#include "asm/assembler/asm_op_defs_impl.h"
#include "utils/debug.h"

#define MAKE_RET(e) \
	Error err{ FromAsmJit(static_cast<asmjit::ErrorCode>(impl_->assembler_.e)) }; \
	if (impl_->config_.assert_every_inst) { \
		GEEK_ASSERT(err.IsSuccess(), "Assembler make instruction failed:", err.msg()); \
	} \
	return err
#define _GEEK_ASM_INST_0X_IMPL(op)								\
	_GEEK_ASM_INST_0X(Assembler::op) {							\
		MAKE_RET(op());		\
	}

#define _GEEK_ASM_INST_1X_IMPL(op, t0)								\
	_GEEK_ASM_INST_1X(Assembler::op, t0) {							\
		MAKE_RET(op(ToAsmJit(o0)));\
	}

#define _GEEK_ASM_INST_2X_IMPL(op, t0, t1)											\
	_GEEK_ASM_INST_2X(Assembler::op, t0, t1) {										\
		MAKE_RET(op(ToAsmJit(o0), ToAsmJit(o1)));	\
	}

#define _GEEK_ASM_INST_3X_IMPL(op, t0, t1, t2)													\
	_GEEK_ASM_INST_3X(Assembler::op, t0, t1, t2) {												\
		MAKE_RET(op(ToAsmJit(o0), ToAsmJit(o1), ToAsmJit(o2)));\
	}

#define _GEEK_ASM_INST_1C_IMPL(op, t0)	\
  _GEEK_ASM_INST_1X_IMPL(op##a, t0);		\
  _GEEK_ASM_INST_1X_IMPL(op##ae, t0);	\
  _GEEK_ASM_INST_1X_IMPL(op##b, t0);		\
  _GEEK_ASM_INST_1X_IMPL(op##be, t0);	\
  _GEEK_ASM_INST_1X_IMPL(op##c, t0);		\
  _GEEK_ASM_INST_1X_IMPL(op##e, t0);		\
  _GEEK_ASM_INST_1X_IMPL(op##g, t0);		\
  _GEEK_ASM_INST_1X_IMPL(op##ge, t0);	\
  _GEEK_ASM_INST_1X_IMPL(op##l, t0);		\
  _GEEK_ASM_INST_1X_IMPL(op##le, t0);	\
  _GEEK_ASM_INST_1X_IMPL(op##na, t0);	\
  _GEEK_ASM_INST_1X_IMPL(op##nae, t0);	\
  _GEEK_ASM_INST_1X_IMPL(op##nb, t0);	\
  _GEEK_ASM_INST_1X_IMPL(op##nbe, t0);	\
  _GEEK_ASM_INST_1X_IMPL(op##nc, t0);	\
  _GEEK_ASM_INST_1X_IMPL(op##ne, t0);	\
  _GEEK_ASM_INST_1X_IMPL(op##ng, t0);	\
  _GEEK_ASM_INST_1X_IMPL(op##nge, t0);	\
  _GEEK_ASM_INST_1X_IMPL(op##nl, t0);	\
  _GEEK_ASM_INST_1X_IMPL(op##nle, t0);	\
  _GEEK_ASM_INST_1X_IMPL(op##no, t0);	\
  _GEEK_ASM_INST_1X_IMPL(op##np, t0);	\
  _GEEK_ASM_INST_1X_IMPL(op##ns, t0);	\
  _GEEK_ASM_INST_1X_IMPL(op##nz, t0);	\
  _GEEK_ASM_INST_1X_IMPL(op##o, t0);		\
  _GEEK_ASM_INST_1X_IMPL(op##p, t0);		\
  _GEEK_ASM_INST_1X_IMPL(op##pe, t0);	\
  _GEEK_ASM_INST_1X_IMPL(op##po, t0);	\
  _GEEK_ASM_INST_1X_IMPL(op##s, t0);		\
  _GEEK_ASM_INST_1X_IMPL(op##z, t0)

namespace geek {
namespace {
asmjit::JitRuntime* Runtime() {
	static asmjit::JitRuntime inst;
	return &inst;
}
}

Assembler::~Assembler() {}

void Assembler::FuncDeleter::operator()(void* ptr) const { Runtime()->release(ptr); }

Assembler::Assembler(Arch arch) { impl_ = std::make_unique<Impl>(this, arch, Runtime()); }

Arch Assembler::GetArch() const { return impl_->arch_; }

const Assembler::Config& Assembler::GetConfig() const { return impl_->config_; }
Assembler::Config& Assembler::GetConfig() { return impl_->config_; }

asm_op::Label Assembler::NewLabel() {
	asm_op::Label ret;
	ret.impl_ = std::make_unique<asm_op::Label::Impl>(impl_->assembler_.newLabel());
	return ret;
}

asm_op::Label Assembler::NewNamedLabel(std::string_view name, asm_op::Label::Type type) {
	asm_op::Label ret;
	ret.impl_ = std::make_unique<asm_op::Label::Impl>(
		impl_->assembler_.newNamedLabel(name.data(), name.size(), ToAsmJit(type)));
	return ret;
}

Assembler::Error Assembler::bind(const asm_op::Label& label) {
	auto e = impl_->assembler_.bind(ToAsmJit(label));
	return FromAsmJit(static_cast<asmjit::ErrorCode>(e));
}

size_t Assembler::CodeSize() const { return impl_->code_.codeSize(); }

const uint8_t* Assembler::CodeBuffer() const { return impl_->code_.sectionById(0)->data(); }

size_t Assembler::PackCodeTo(uint8_t* ptr, size_t size, uint64_t base_address) const {
	auto ec = impl_->code_.relocateToBase(base_address);
	Error err = FromAsmJit(static_cast<asmjit::ErrorCode>(ec));
	GEEK_ASSERT(err.IsSuccess(), "Assembler relocate code to base failed:", err.msg());

	auto s = std::min(size, CodeSize());
	memcpy(ptr, CodeBuffer(), s);
	return s;
}

std::unique_ptr<void, Assembler::FuncDeleter> Assembler::PackToFuncImpl() const {
	void* func;
	Runtime()->add(&func, &impl_->code_);
	return std::unique_ptr<void, FuncDeleter>(func);
}

Assembler::Error::Error(ErrorCode code)
	: code_(code) {}

std::string Assembler::Error::msg() const { return asmjit::DebugUtils::errorAsString(ToAsmJit(code_)); }

bool Assembler::Error::IsSuccess() const { return code() == kErrorOk; }

_GEEK_ASM_INST_0X_IMPL(cbw)
_GEEK_ASM_INST_0X_IMPL(cdq)
_GEEK_ASM_INST_0X_IMPL(cdqe)
_GEEK_ASM_INST_2X_IMPL(cmpxchg, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(cmpxchg, Mem, Gp)
_GEEK_ASM_INST_1X_IMPL(cmpxchg16b, Mem)
_GEEK_ASM_INST_1X_IMPL(cmpxchg8b, Mem)
_GEEK_ASM_INST_0X_IMPL(cqo)
_GEEK_ASM_INST_0X_IMPL(cwd)
_GEEK_ASM_INST_0X_IMPL(cwde)
_GEEK_ASM_INST_1X_IMPL(div, Gp)
_GEEK_ASM_INST_1X_IMPL(div, Mem)
_GEEK_ASM_INST_1X_IMPL(idiv, Gp)
_GEEK_ASM_INST_1X_IMPL(idiv, Mem)
_GEEK_ASM_INST_1X_IMPL(imul, Gp)
_GEEK_ASM_INST_1X_IMPL(imul, Mem)
_GEEK_ASM_INST_0X_IMPL(iret)
_GEEK_ASM_INST_0X_IMPL(iretd)
_GEEK_ASM_INST_0X_IMPL(iretq)
_GEEK_ASM_INST_1X_IMPL(jecxz, Label)
_GEEK_ASM_INST_1X_IMPL(jecxz, Imm)
_GEEK_ASM_INST_1X_IMPL(loop, Label)
_GEEK_ASM_INST_1X_IMPL(loop, Imm)
_GEEK_ASM_INST_1X_IMPL(loope, Label)
_GEEK_ASM_INST_1X_IMPL(loope, Imm)
_GEEK_ASM_INST_1X_IMPL(loopne, Label)
_GEEK_ASM_INST_1X_IMPL(loopne, Imm)
_GEEK_ASM_INST_1X_IMPL(mul, Gp)
_GEEK_ASM_INST_1X_IMPL(mul, Mem)
_GEEK_ASM_INST_0X_IMPL(ret)
_GEEK_ASM_INST_1X_IMPL(ret, Imm)
_GEEK_ASM_INST_0X_IMPL(retf)
_GEEK_ASM_INST_1X_IMPL(retf, Imm)
_GEEK_ASM_INST_0X_IMPL(xlatb)


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
_GEEK_ASM_INST_1C_IMPL(j, Label);
_GEEK_ASM_INST_1C_IMPL(j, Imm);
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
_GEEK_ASM_INST_1C_IMPL(set, Gp);
_GEEK_ASM_INST_1C_IMPL(set, Mem);
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


_GEEK_ASM_INST_2X_IMPL(arpl, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(arpl, Mem, Gp)
_GEEK_ASM_INST_0X_IMPL(cli)
_GEEK_ASM_INST_0X_IMPL(getsec)
_GEEK_ASM_INST_1X_IMPL(int_, Imm)
_GEEK_ASM_INST_0X_IMPL(int3)
_GEEK_ASM_INST_0X_IMPL(into)
_GEEK_ASM_INST_2X_IMPL(lar, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(lar, Gp, Mem)
_GEEK_ASM_INST_2X_IMPL(lds, Gp, Mem)
_GEEK_ASM_INST_2X_IMPL(les, Gp, Mem)
_GEEK_ASM_INST_2X_IMPL(lfs, Gp, Mem)
_GEEK_ASM_INST_2X_IMPL(lgs, Gp, Mem)
_GEEK_ASM_INST_2X_IMPL(lsl, Gp, Gp)
_GEEK_ASM_INST_2X_IMPL(lsl, Gp, Mem)
_GEEK_ASM_INST_2X_IMPL(lss, Gp, Mem)
_GEEK_ASM_INST_0X_IMPL(pause)
_GEEK_ASM_INST_0X_IMPL(rsm)
_GEEK_ASM_INST_1X_IMPL(sgdt, Mem)
_GEEK_ASM_INST_1X_IMPL(sidt, Mem)
_GEEK_ASM_INST_1X_IMPL(sldt, Gp)
_GEEK_ASM_INST_1X_IMPL(sldt, Mem)
_GEEK_ASM_INST_1X_IMPL(smsw, Gp)
_GEEK_ASM_INST_1X_IMPL(smsw, Mem)
_GEEK_ASM_INST_0X_IMPL(sti)
_GEEK_ASM_INST_1X_IMPL(str, Gp)
_GEEK_ASM_INST_1X_IMPL(str, Mem)
_GEEK_ASM_INST_1X_IMPL(verr, Gp)
_GEEK_ASM_INST_1X_IMPL(verr, Mem)
_GEEK_ASM_INST_1X_IMPL(verw, Gp)
_GEEK_ASM_INST_1X_IMPL(verw, Mem)

//! \name Core Privileged Instructions
//! \{

_GEEK_ASM_INST_0X_IMPL(clts)
_GEEK_ASM_INST_0X_IMPL(hlt)
_GEEK_ASM_INST_0X_IMPL(invd)
_GEEK_ASM_INST_1X_IMPL(invlpg, Mem)
_GEEK_ASM_INST_2X_IMPL(invpcid, Gp, Mem)
_GEEK_ASM_INST_1X_IMPL(lgdt, Mem)
_GEEK_ASM_INST_1X_IMPL(lidt, Mem)
_GEEK_ASM_INST_1X_IMPL(lldt, Gp)
_GEEK_ASM_INST_1X_IMPL(lldt, Mem)
_GEEK_ASM_INST_1X_IMPL(lmsw, Gp)
_GEEK_ASM_INST_1X_IMPL(lmsw, Mem)
_GEEK_ASM_INST_1X_IMPL(ltr, Gp)
_GEEK_ASM_INST_1X_IMPL(ltr, Mem)
_GEEK_ASM_INST_3X_IMPL(rdmsr, Gp_EDX, Gp_EAX, Gp_ECX)
_GEEK_ASM_INST_3X_IMPL(rdpmc, Gp_EDX, Gp_EAX, Gp_ECX)
_GEEK_ASM_INST_0X_IMPL(swapgs)
_GEEK_ASM_INST_0X_IMPL(wbinvd)
_GEEK_ASM_INST_0X_IMPL(wbnoinvd)
_GEEK_ASM_INST_3X_IMPL(wrmsr, Gp_EDX, Gp_EAX, Gp_ECX)
_GEEK_ASM_INST_3X_IMPL(xsetbv, Gp_EDX, Gp_EAX, Gp_ECX)


Assembler::Error Assembler::db(uint8_t x, size_t repeat_count) { MAKE_RET(db(x, repeat_count)); }

Assembler::Error Assembler::dw(uint16_t x, size_t repeat_count) { MAKE_RET(dw(x, repeat_count)); }

Assembler::Error Assembler::dd(uint32_t x, size_t repeat_count) { MAKE_RET(dd(x, repeat_count)); }

Assembler::Error Assembler::dq(uint64_t x, size_t repeat_count) { MAKE_RET(dq(x, repeat_count)); }

Assembler::Error Assembler::Embed(const void* data, size_t data_size) { MAKE_RET(embed(data, data_size)); }

Assembler::Error Assembler::EmbedInt8(int8_t value, size_t repeat_count) { MAKE_RET(embedInt8(value, repeat_count)); }

Assembler::Error Assembler::EmbedUInt8(uint8_t value, size_t repeat_count) {
	MAKE_RET(embedUInt8(value, repeat_count));
}

Assembler::Error Assembler::EmbedInt16(int16_t value, size_t repeat_count) {
	MAKE_RET(embedInt16(value, repeat_count));
}

Assembler::Error Assembler::EmbedUInt16(uint16_t value, size_t repeat_count) {
	MAKE_RET(embedUInt16(value, repeat_count));
}

Assembler::Error Assembler::EmbedInt32(int32_t value, size_t repeat_count) {
	MAKE_RET(embedInt32(value, repeat_count));
}

Assembler::Error Assembler::EmbedUInt32(uint32_t value, size_t repeat_count) {
	MAKE_RET(embedUInt32(value, repeat_count));
}

Assembler::Error Assembler::EmbedInt64(int64_t value, size_t repeat_count) {
	MAKE_RET(embedInt64(value, repeat_count));
}

Assembler::Error Assembler::EmbedUInt64(uint64_t value, size_t repeat_count) {
	MAKE_RET(embedUInt64(value, repeat_count));
}

Assembler::Error Assembler::EmbedFloat(float value, size_t repeat_count) { MAKE_RET(embedFloat(value, repeat_count)); }

Assembler::Error Assembler::EmbedDouble(double value, size_t repeat_count) {
	MAKE_RET(embedDouble(value, repeat_count));
}

Assembler::Error Assembler::EmbedLabel(const asm_op::Label& label, size_t data_size) {
	MAKE_RET(embedLabel(ToAsmJit(label), data_size));
}

Assembler::Error Assembler::EmbedLabelDelta(const asm_op::Label& label, const asm_op::Label& base, size_t data_size) {
	MAKE_RET(embedLabelDelta(ToAsmJit(label), ToAsmJit(base), data_size));
}
}
