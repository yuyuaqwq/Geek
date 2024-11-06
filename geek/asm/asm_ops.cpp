#include <geek/asm/asm_ops.h>

#include "assembler_impl.h"
#include "assembler_p_impl.h"

namespace geek {
namespace asm_ops {
Mem ptr(const Gp& base, int32_t offset, uint32_t size) {
	Mem m;
	m.impl_ = std::make_unique<Mem::Impl>(asmjit::x86::ptr(ToAsmJit(base), offset, size));
	return m;
}

Mem ptr(const Gp& base, const Gp& index, uint32_t shift, int32_t offset, uint32_t size) {
	Mem m;
	m.impl_ = std::make_unique<Mem::Impl>(asmjit::x86::ptr(ToAsmJit(base), ToAsmJit(index), shift, offset, size));
	return m;
}

Mem ptr(const Gp& base, const Vec& index, uint32_t shift, int32_t offset, uint32_t size) {
	Mem m;
	m.impl_ = std::make_unique<Mem::Impl>(asmjit::x86::ptr(ToAsmJit(base), ToAsmJit(index), shift, offset, size));
	return m;
}

Mem ptr(const Label& base, int32_t offset, uint32_t size) {
	Mem m;
	m.impl_ = std::make_unique<Mem::Impl>(asmjit::x86::ptr(ToAsmJit(base), offset, size));
	return m;
}

Mem ptr(const Label& base, const Gp& index, uint32_t shift, int32_t offset, uint32_t size) {
	Mem m;
	m.impl_ = std::make_unique<Mem::Impl>(asmjit::x86::ptr(ToAsmJit(base), ToAsmJit(index), shift, offset, size));
	return m;
}

Mem ptr(const Label& base, const Vec& index, uint32_t shift, int32_t offset, uint32_t size) {
	Mem m;
	m.impl_ = std::make_unique<Mem::Impl>(asmjit::x86::ptr(ToAsmJit(base), ToAsmJit(index), shift, offset, size));
	return m;
}

Mem ptr(const Rip& rip_, int32_t offset, uint32_t size) {
	Mem m;
	m.impl_ = std::make_unique<Mem::Impl>(asmjit::x86::ptr(ToAsmJit(rip_), offset, size));
	return m;
}

Mem ptr(uint64_t base, uint32_t size) {
	Mem m;
	m.impl_ = std::make_unique<Mem::Impl>(asmjit::x86::ptr(base, size));
	return m;
}

Mem ptr(uint64_t base, const Reg& index, uint32_t shift, uint32_t size) {
	Mem m;
	m.impl_ = std::make_unique<Mem::Impl>(asmjit::x86::ptr(base, ToAsmJit(index), shift, size));
	return m;
}

Mem ptr(uint64_t base, const Vec& index, uint32_t shift, uint32_t size) {
	Mem m;
	m.impl_ = std::make_unique<Mem::Impl>(asmjit::x86::ptr(base, ToAsmJit(index), shift, size));
	return m;
}

Mem ptr_abs(uint64_t base, uint32_t size) {
	Mem m;
	m.impl_ = std::make_unique<Mem::Impl>(asmjit::x86::ptr_abs(base, size));
	return m;
}

Mem ptr_abs(uint64_t base, const Reg& index, uint32_t shift, uint32_t size) {
	Mem m;
	m.impl_ = std::make_unique<Mem::Impl>(asmjit::x86::ptr_abs(base, ToAsmJit(index), shift, size));
	return m;
}

Mem ptr_abs(uint64_t base, const Vec& index, uint32_t shift, uint32_t size) {
	Mem m;
	m.impl_ = std::make_unique<Mem::Impl>(asmjit::x86::ptr_abs(base, ToAsmJit(index), shift, size));
	return m;
}

Mem ptr_rel(uint64_t base, uint32_t size) {
	Mem m;
	m.impl_ = std::make_unique<Mem::Impl>(asmjit::x86::ptr_rel(base, size));
	return m;
}

Mem ptr_rel(uint64_t base, const Reg& index, uint32_t shift, uint32_t size) {
	Mem m;
	m.impl_ = std::make_unique<Mem::Impl>(asmjit::x86::ptr_rel(base, ToAsmJit(index), shift, size));
	return m;
}

Mem ptr_rel(uint64_t base, const Vec& index, uint32_t shift, uint32_t size) {
	Mem m;
	m.impl_ = std::make_unique<Mem::Impl>(asmjit::x86::ptr_rel(base, ToAsmJit(index), shift, size));
	return m;
}
}
}
