#include "assembler_impl.h"

#include <cassert>

#include <mutex>

#include "mem_impl.h"

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

internal::Mem asm_ptr(regs base, int32_t offset, uint32_t size)
{
	internal::Mem m;
	if (auto b = ToAsmJitRip(base)) {
		m.impl_ = std::make_unique<internal::Mem::Impl>(
			ptr(*b, offset, size));
	}
	else if (auto b = ToAsmJitGp(base)) {
		m.impl_ = std::make_unique<internal::Mem::Impl>(
			ptr(*b, offset, size));
	}
	else {
		throw std::exception("Unsupported register type of parameter: base");
	}
	return m;
}

internal::Mem asm_ptr(regs base, regs index, uint32_t shift, int32_t offset, uint32_t size)
{
	internal::Mem m;

	auto b = ToAsmJitGp(base);
	GEEK_ASSERT(b);

	if (auto i = ToAsmJitGp(index)) {
		m.impl_ = std::make_unique<internal::Mem::Impl>(
			ptr(*b, *i, shift, offset, size));
	}
	else if (auto i = ToAsmJitVec(index)) {
		m.impl_ = std::make_unique<internal::Mem::Impl>(
			ptr(*b, *i, shift, offset, size));
	}
	else {
		throw std::exception("Unsupported register type of parameter: index");
	}

	return m;
}

internal::Mem asm_ptr(uint64_t base, uint32_t size)
{
	internal::Mem m;
	m.impl_ = std::make_unique<internal::Mem::Impl>(
		asmjit::x86::ptr(base, size));
	return m;
}

internal::Mem asm_ptr(uint64_t base, regs index, uint32_t shift, uint32_t size)
{
	internal::Mem m;
	if (auto i = ToAsmJitVec(index)) {
		m.impl_ = std::make_unique<internal::Mem::Impl>(
			ptr(base, *i, shift, size));
	}
	else if (auto i = ToAsmJit(index)) {
		m.impl_ = std::make_unique<internal::Mem::Impl>(
			ptr(base, *i, shift, size));
	}
	else {
		throw std::exception("Unsupported register type of parameter: index");
	}

	return m;
}

Assembler::Error::Error(ErrorCode code)
	: code_(code)
{
}

std::string Assembler::Error::msg() const
{
	return asmjit::DebugUtils::errorAsString(ToAsmJit(code_));
}

Assembler Assembler::Alloc(Arch arch)
{
	return { arch };
}

#define GEEK_INST_2X_IMPL_(op, t1, t2, g1, g2)					\
	Assembler::Error Assembler::op(t1 o1, t2 o2) {				\
		auto e = impl_->assembler_.mov(g1, g2);					\
		return FromAsmJit(static_cast<asmjit::ErrorCode>(e));	\
	}

#define GEEK_INST_2X_IMPL_REG_REG(op, r1, r2) \
	GEEK_INST_2X_IMPL_(op, regs, regs, *ToAsmJit##r1(o1), *ToAsmJit##r2(o2))

#define GEEK_INST_2X_IMPL_REG_T(op, r1, t2) \
	GEEK_INST_2X_IMPL_(op, regs, const internal::t2&, *ToAsmJit##r1(o1), ToAsmJit(o2))

#define GEEK_INST_2X_IMPL_T_REG(op, t1, r2) \
	GEEK_INST_2X_IMPL_(op, const internal::t1&, regs, ToAsmJit(o1), *ToAsmJit##Gp(o2))

#define GEEK_INST_2X_IMPL_T_T(op, t1, t2) \
	GEEK_INST_2X_IMPL_(op, const internal::t1&, const internal::t2&, ToAsmJit(o1), ToAsmJit(o2))

GEEK_INST_2X_IMPL_REG_REG(mov, Gp, Gp)
GEEK_INST_2X_IMPL_REG_T(mov, Gp, Imm)
GEEK_INST_2X_IMPL_REG_T(mov, Gp, Mem)
GEEK_INST_2X_IMPL_T_REG(mov, Mem, GP)
GEEK_INST_2X_IMPL_T_T(mov, Mem, Imm)


Assembler::Assembler(Arch arch)
{
	impl_ = std::make_unique<Impl>(this, arch, Runtime());
}
}
