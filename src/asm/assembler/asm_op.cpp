#include <geek/asm/assembler/asm_op.h>

#include "asm/assembler_impl.h"
#include "asm/assembler/asm_op_defs_impl.h"

#define _GEEK_ASM_MEM_PTR_IMPL(op)                                                          \
	Mem op(const Gp& base, int32_t offset) { 		 \
		return ToMem(asmjit::x86::op(ToAsmJit(base), offset)); 	\
	}																						\
	Mem op(const Gp& base, const Gp& index, uint32_t shift, int32_t offset) { 		 \
		return ToMem(asmjit::x86::op(ToAsmJit(base), ToAsmJit(index), shift, offset)); 	\
	}																						\
	Mem op(const Gp& base, const Vec& index, uint32_t shift, int32_t offset) { 		 \
		return ToMem(asmjit::x86::op(ToAsmJit(base), ToAsmJit(index), shift, offset)); 	\
	}																						\
	Mem op(const Label& base, int32_t offset) { 		 \
		return ToMem(asmjit::x86::op(ToAsmJit(base), offset)); 	\
	}																						\
	Mem op(const Label& base, const Gp& index, uint32_t shift, int32_t offset) { 		\
		return ToMem(asmjit::x86::op(ToAsmJit(base), ToAsmJit(index), shift, offset)); 	\
	}																						\
	Mem op(const Rip& rip_, int32_t offset) { 		 \
		return ToMem(asmjit::x86::op(ToAsmJit(rip_), offset)); 	\
	}																						\
	Mem op(uint64_t base) { 		 \
		return ToMem(asmjit::x86::op(base)); 	\
	}																						\
	Mem op(uint64_t base, const Gp& index, uint32_t shift) { 		 \
		return ToMem(asmjit::x86::op(base, ToAsmJit(index), shift)); 	\
	}																						\
	Mem op(uint64_t base, const Vec& index, uint32_t shift) { 		 \
		return ToMem(asmjit::x86::op(base, ToAsmJit(index), shift)); 	\
	}																						\
	Mem op##_abs(uint64_t base) { 		 \
		return ToMem(asmjit::x86::op##_abs(base)); 	\
	}																						\
	Mem op##_abs(uint64_t base, const Gp& index, uint32_t shift) { 		 \
		return ToMem(asmjit::x86::op##_abs(base, ToAsmJit(index), shift)); 	\
	}																						\
	Mem op##_abs(uint64_t base, const Vec& index, uint32_t shift) { 		 \
		return ToMem(asmjit::x86::op##_abs(base, ToAsmJit(index), shift)); 	\
	}																						\
	Mem op##_rel(uint64_t base) { 		 \
		return ToMem(asmjit::x86::op##_rel(base)); 	\
	}																						\
	Mem op##_rel(uint64_t base, const Gp& index, uint32_t shift) { 		 \
		return ToMem(asmjit::x86::op##_rel(base, ToAsmJit(index), shift)); 	\
	}																						\
	Mem op##_rel(uint64_t base, const Vec& index, uint32_t shift) { 		 \
		return ToMem(asmjit::x86::op##_rel(base, ToAsmJit(index), shift)); 	\
	}																						\

namespace geek {
namespace asm_op {
namespace {
Mem ToMem(asmjit::x86::Mem&& m) {
	Mem ret;
	ret.impl_ = std::make_unique<Mem::Impl>(std::move(m));
	return ret;
}
}

Mem ptr(const Gp& base, int32_t offset, uint32_t size) {
	return ToMem(asmjit::x86::ptr(ToAsmJit(base), offset, size));
}

Mem ptr(const Gp& base, const Gp& index, uint32_t shift, int32_t offset, uint32_t size) {
	return ToMem(asmjit::x86::ptr(ToAsmJit(base), ToAsmJit(index), shift, offset, size));
}

Mem ptr(const Gp& base, const Vec& index, uint32_t shift, int32_t offset, uint32_t size) {
	return ToMem(asmjit::x86::ptr(ToAsmJit(base), ToAsmJit(index), shift, offset, size));
}

Mem ptr(const Label& base, int32_t offset, uint32_t size) {
	return ToMem(asmjit::x86::ptr(ToAsmJit(base), offset, size));	
}

Mem ptr(const Label& base, const Gp& index, uint32_t shift, int32_t offset, uint32_t size) {
	return ToMem(asmjit::x86::ptr(ToAsmJit(base), ToAsmJit(index), shift, offset, size));	
}

Mem ptr(const Label& base, const Vec& index, uint32_t shift, int32_t offset, uint32_t size) {
	return ToMem(asmjit::x86::ptr(ToAsmJit(base), ToAsmJit(index), shift, offset, size));	
}

Mem ptr(const Rip& rip_, int32_t offset, uint32_t size) {
	return ToMem(asmjit::x86::ptr(ToAsmJit(rip_), offset, size));	
}

Mem ptr(uint64_t base, uint32_t size) {
	return ToMem(asmjit::x86::ptr(base, size));	
}

Mem ptr(uint64_t base, const Reg& index, uint32_t shift, uint32_t size) {
	return ToMem(asmjit::x86::ptr(base, ToAsmJit(index), shift, size));	
}

Mem ptr(uint64_t base, const Vec& index, uint32_t shift, uint32_t size) {
	return ToMem(asmjit::x86::ptr(base, ToAsmJit(index), shift, size));	
}

Mem ptr_abs(uint64_t base, uint32_t size) {
	return ToMem(asmjit::x86::ptr_abs(base, size));	
}

Mem ptr_abs(uint64_t base, const Reg& index, uint32_t shift, uint32_t size) {
	return ToMem(asmjit::x86::ptr_abs(base, ToAsmJit(index), shift, size));	
}

Mem ptr_abs(uint64_t base, const Vec& index, uint32_t shift, uint32_t size) {
	return ToMem(asmjit::x86::ptr_abs(base, ToAsmJit(index), shift, size));	
}

Mem ptr_rel(uint64_t base, uint32_t size) {
	return ToMem(asmjit::x86::ptr_rel(base, size));	
}

Mem ptr_rel(uint64_t base, const Reg& index, uint32_t shift, uint32_t size) {
	return ToMem(asmjit::x86::ptr_rel(base, ToAsmJit(index), shift, size));	
}

Mem ptr_rel(uint64_t base, const Vec& index, uint32_t shift, uint32_t size) {
	return ToMem(asmjit::x86::ptr_rel(base, ToAsmJit(index), shift, size));	
}


// Definition of memory operand constructors that use platform independent naming.
_GEEK_ASM_MEM_PTR_IMPL(ptr_8);
_GEEK_ASM_MEM_PTR_IMPL(ptr_16);
_GEEK_ASM_MEM_PTR_IMPL(ptr_32);
_GEEK_ASM_MEM_PTR_IMPL(ptr_48);
_GEEK_ASM_MEM_PTR_IMPL(ptr_64);
_GEEK_ASM_MEM_PTR_IMPL(ptr_80);
_GEEK_ASM_MEM_PTR_IMPL(ptr_128);
_GEEK_ASM_MEM_PTR_IMPL(ptr_256);
_GEEK_ASM_MEM_PTR_IMPL(ptr_512);

// Definition of memory operand constructors that use X86-specific convention.
_GEEK_ASM_MEM_PTR_IMPL(byte_ptr);
_GEEK_ASM_MEM_PTR_IMPL(word_ptr);
_GEEK_ASM_MEM_PTR_IMPL(dword_ptr);
_GEEK_ASM_MEM_PTR_IMPL(fword_ptr);
_GEEK_ASM_MEM_PTR_IMPL(qword_ptr);
_GEEK_ASM_MEM_PTR_IMPL(tbyte_ptr);
_GEEK_ASM_MEM_PTR_IMPL(tword_ptr);
_GEEK_ASM_MEM_PTR_IMPL(oword_ptr);
_GEEK_ASM_MEM_PTR_IMPL(dqword_ptr);
_GEEK_ASM_MEM_PTR_IMPL(qqword_ptr);
_GEEK_ASM_MEM_PTR_IMPL(xmmword_ptr);
_GEEK_ASM_MEM_PTR_IMPL(ymmword_ptr);
_GEEK_ASM_MEM_PTR_IMPL(zmmword_ptr);
}
}
