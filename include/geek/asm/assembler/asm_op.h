#pragma once
#include <geek/asm/assembler/asm_op_defs.h>

namespace geek {
namespace asm_op {
//! Creates `[base.reg + offset]` memory operand.
Mem ptr(const Gp& base, int32_t offset = 0, uint32_t size = 0);
//! Creates `[base.reg + (index << shift) + offset]` memory operand (scalar index).
Mem ptr(const Gp& base, const Gp& index, uint32_t shift = 0, int32_t offset = 0, uint32_t size = 0);
//! Creates `[base.reg + (index << shift) + offset]` memory operand (vector index).
Mem ptr(const Gp& base, const Vec& index, uint32_t shift = 0, int32_t offset = 0, uint32_t size = 0);
//! Creates `[base + offset]` memory operand.
Mem ptr(const Label& base, int32_t offset = 0, uint32_t size = 0);
//! Creates `[base + (index << shift) + offset]` memory operand.
Mem ptr(const Label& base, const Gp& index, uint32_t shift = 0, int32_t offset = 0, uint32_t size = 0);
//! Creates `[base + (index << shift) + offset]` memory operand.
Mem ptr(const Label& base, const Vec& index, uint32_t shift = 0, int32_t offset = 0, uint32_t size = 0);
//! Creates `[rip + offset]` memory operand.
Mem ptr(const Rip& rip_, int32_t offset = 0, uint32_t size = 0);
//! Creates `[base]` absolute memory operand.
Mem ptr(uint64_t base, uint32_t size = 0);
//! Creates `[base + (index.reg << shift)]` absolute memory operand.
Mem ptr(uint64_t base, const Reg& index, uint32_t shift = 0, uint32_t size = 0);
//! Creates `[base + (index.reg << shift)]` absolute memory operand.
Mem ptr(uint64_t base, const Vec& index, uint32_t shift = 0, uint32_t size = 0);
//! Creates `[base]` absolute memory operand (absolute).
Mem ptr_abs(uint64_t base, uint32_t size = 0);
//! Creates `[base + (index.reg << shift)]` absolute memory operand (absolute).
Mem ptr_abs(uint64_t base, const Reg& index, uint32_t shift = 0, uint32_t size = 0);
//! Creates `[base + (index.reg << shift)]` absolute memory operand (absolute).
Mem ptr_abs(uint64_t base, const Vec& index, uint32_t shift = 0, uint32_t size = 0);
//! Creates `[base]` relative memory operand (relative).
Mem ptr_rel(uint64_t base, uint32_t size = 0);
//! Creates `[base + (index.reg << shift)]` relative memory operand (relative).
Mem ptr_rel(uint64_t base, const Reg& index, uint32_t shift = 0, uint32_t size = 0);
//! Creates `[base + (index.reg << shift)]` relative memory operand (relative).
Mem ptr_rel(uint64_t base, const Vec& index, uint32_t shift = 0, uint32_t size = 0);


// Definition of memory operand constructors that use platform independent naming.
_GEEK_ASM_MEM_PTR(ptr_8);
_GEEK_ASM_MEM_PTR(ptr_16);
_GEEK_ASM_MEM_PTR(ptr_32);
_GEEK_ASM_MEM_PTR(ptr_48);
_GEEK_ASM_MEM_PTR(ptr_64);
_GEEK_ASM_MEM_PTR(ptr_80);
_GEEK_ASM_MEM_PTR(ptr_128);
_GEEK_ASM_MEM_PTR(ptr_256);
_GEEK_ASM_MEM_PTR(ptr_512);

// Definition of memory operand constructors that use X86-specific convention.
_GEEK_ASM_MEM_PTR(byte_ptr);
_GEEK_ASM_MEM_PTR(word_ptr);
_GEEK_ASM_MEM_PTR(dword_ptr);
_GEEK_ASM_MEM_PTR(fword_ptr);
_GEEK_ASM_MEM_PTR(qword_ptr);
_GEEK_ASM_MEM_PTR(tbyte_ptr);
_GEEK_ASM_MEM_PTR(tword_ptr);
_GEEK_ASM_MEM_PTR(oword_ptr);
_GEEK_ASM_MEM_PTR(dqword_ptr);
_GEEK_ASM_MEM_PTR(qqword_ptr);
_GEEK_ASM_MEM_PTR(xmmword_ptr);
_GEEK_ASM_MEM_PTR(ymmword_ptr);
_GEEK_ASM_MEM_PTR(zmmword_ptr);
}
}