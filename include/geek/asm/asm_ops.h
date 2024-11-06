#pragma once
#include <geek/asm/assembler_p.h>

namespace geek {
namespace asm_ops {
using namespace internal;
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
}

}