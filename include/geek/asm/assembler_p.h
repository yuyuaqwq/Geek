#pragma once
#include <type_traits>
#include <geek/global.h>

#define _GEEK_ASM_INST_0X(op) \
	geek::Assembler::Error op()
#define _GEEK_ASM_INST_1X(op, t0) \
	geek::Assembler::Error op(const geek::internal::t0& o0)
#define _GEEK_ASM_INST_2X(op, t0, t1) \
	geek::Assembler::Error op(const geek::internal::t0& o0, const geek::internal::t1& o1)
#define _GEEK_ASM_INST_3X(op, t0, t1, t2) \
	geek::Assembler::Error op(const geek::internal::t0& o0, const geek::internal::t1& o1, const geek::internal::t2& o2)

namespace geek {
namespace internal {
class Imm {
public:
	template<class T>
	static constexpr bool IsConstexprConstructible = std::is_integral_v<T>
												  || std::is_enum_v<T>
												  || std::is_pointer_v<T>
												  || std::is_function_v<T>;

	template<class T, class = typename std::enable_if_t<IsConstexprConstructible<std::decay_t<T>>>>
	constexpr Imm(const T& val) noexcept {
		data_.u64 = static_cast<uint64_t>(val);
		index_ = 0;
	}

	Imm(const float& f) noexcept { data_.f = f; index_ = 1; }
	Imm(const double& d) noexcept { data_.d = d; index_ = 2; }

	bool is_integral() const { return index_ == 0; }
	bool is_float() const { return index_ == 1; }
	bool is_double() const { return index_ == 2; }

	auto integral() const { return data_.u64; }
	auto float_() const { return data_.f; }
	auto double_() const { return data_.d; }

private:
	union 
	{
		uint64_t u64;
		float f;
		double d;
	} data_;
	uint8_t index_;
};

class Mem {
public:
	Mem() = default;
	~Mem();

	Mem(const Mem& right);
	Mem(Mem&& right) noexcept;

	_GEEK_PUB_IMPL
};

class Label {
public:
	Label() = default;
	~Label();

	Label(const Label& right);
	Label(Label&& right) noexcept;

	_GEEK_PUB_IMPL
};


enum class RegisterId : uint32_t {
	al,
	bl,
	cl,
	dl,
	spl,
	bpl,
	sil,
	dil,
	r8b,
	r9b,
	r10b,
	r11b,
	r12b,
	r13b,
	r14b,
	r15b,

	ah,
	bh,
	ch,
	dh,
	ax,
	bx,
	cx,
	dx,
	sp,
	bp,
	si,
	di,
	r8w,
	r9w,
	r10w,
	r11w,
	r12w,
	r13w,
	r14w,
	r15w,

	eax,
	ebx,
	ecx,
	edx,
	esp,
	ebp,
	esi,
	edi,
	r8d,
	r9d,
	r10d,
	r11d,
	r12d,
	r13d,
	r14d,
	r15d,

	rax,
	rbx,
	rcx,
	rdx,
	rsp,
	rbp,
	rsi,
	rdi,
	r8,
	r9,
	r10,
	r11,
	r12,
	r13,
	r14,
	r15,

	xmm0,
	xmm1,
	xmm2,
	xmm3,
	xmm4,
	xmm5,
	xmm6,
	xmm7,
	xmm8,
	xmm9,
	xmm10,
	xmm11,
	xmm12,
	xmm13,
	xmm14,
	xmm15,
	xmm16,
	xmm17,
	xmm18,
	xmm19,
	xmm20,
	xmm21,
	xmm22,
	xmm23,
	xmm24,
	xmm25,
	xmm26,
	xmm27,
	xmm28,
	xmm29,
	xmm30,
	xmm31,

	ymm0,
	ymm1,
	ymm2,
	ymm3,
	ymm4,
	ymm5,
	ymm6,
	ymm7,
	ymm8,
	ymm9,
	ymm10,
	ymm11,
	ymm12,
	ymm13,
	ymm14,
	ymm15,
	ymm16,
	ymm17,
	ymm18,
	ymm19,
	ymm20,
	ymm21,
	ymm22,
	ymm23,
	ymm24,
	ymm25,
	ymm26,
	ymm27,
	ymm28,
	ymm29,
	ymm30,
	ymm31,

	zmm0,
	zmm1,
	zmm2,
	zmm3,
	zmm4,
	zmm5,
	zmm6,
	zmm7,
	zmm8,
	zmm9,
	zmm10,
	zmm11,
	zmm12,
	zmm13,
	zmm14,
	zmm15,
	zmm16,
	zmm17,
	zmm18,
	zmm19,
	zmm20,
	zmm21,
	zmm22,
	zmm23,
	zmm24,
	zmm25,
	zmm26,
	zmm27,
	zmm28,
	zmm29,
	zmm30,
	zmm31,

	mm0,
	mm1,
	mm2,
	mm3,
	mm4,
	mm5,
	mm6,
	mm7,

	k0,
	k1,
	k2,
	k3,
	k4,
	k5,
	k6,
	k7,

	no_seg,
	es,
	cs,
	ss,
	ds,
	fs,
	gs,

	cr0,
	cr1,
	cr2,
	cr3,
	cr4,
	cr5,
	cr6,
	cr7,
	cr8,
	cr9,
	cr10,
	cr11,
	cr12,
	cr13,
	cr14,
	cr15,

	dr0,
	dr1,
	dr2,
	dr3,
	dr4,
	dr5,
	dr6,
	dr7,
	dr8,
	dr9,
	dr10,
	dr11,
	dr12,
	dr13,
	dr14,
	dr15,

	st0,
	st1,
	st2,
	st3,
	st4,
	st5,
	st6,
	st7,

	bnd0,
	bnd1,
	bnd2,
	bnd3,

	tmm0,
	tmm1,
	tmm2,
	tmm3,
	tmm4,
	tmm5,
	tmm6,
	tmm7,

	rip,
};

class Reg
{
public:
	explicit Reg(RegisterId id);
	~Reg();

	RegisterId id() const { return id_; }

	_GEEK_PUB_IMPL
private:
	RegisterId id_;
};

#define _GEEK_ASM_DEFINE_REG(x, inherit) \
class x : public inherit { \
public: \
	explicit x(RegisterId id) : inherit(id) {} \
};

_GEEK_ASM_DEFINE_REG(Gp, Reg);
_GEEK_ASM_DEFINE_REG(Vec, Reg);
_GEEK_ASM_DEFINE_REG(Mm, Reg);
_GEEK_ASM_DEFINE_REG(SReg, Reg);
_GEEK_ASM_DEFINE_REG(KReg, Reg);
_GEEK_ASM_DEFINE_REG(CReg, Reg);
_GEEK_ASM_DEFINE_REG(DReg, Reg);
_GEEK_ASM_DEFINE_REG(St, Reg);
_GEEK_ASM_DEFINE_REG(Bnd, Reg);
_GEEK_ASM_DEFINE_REG(Tmm, Reg);
_GEEK_ASM_DEFINE_REG(Rip, Reg);

_GEEK_ASM_DEFINE_REG(Gpb, Gp);
_GEEK_ASM_DEFINE_REG(GpbLo, Gpb);
_GEEK_ASM_DEFINE_REG(GpbHi, Gpb);
_GEEK_ASM_DEFINE_REG(Gpw, Gp);
_GEEK_ASM_DEFINE_REG(Gpd, Gp);
_GEEK_ASM_DEFINE_REG(Gpq, Gp);

_GEEK_ASM_DEFINE_REG(Xmm, Vec);
_GEEK_ASM_DEFINE_REG(Ymm, Vec);
_GEEK_ASM_DEFINE_REG(Zmm, Vec);


typedef Gp Gp_AL;
typedef Gp Gp_AH;
typedef Gp Gp_CL;
typedef Gp Gp_AX;
typedef Gp Gp_DX;

typedef Gp Gp_EAX;
typedef Gp Gp_EBX;
typedef Gp Gp_ECX;
typedef Gp Gp_EDX;

typedef Gp Gp_RAX;
typedef Gp Gp_RBX;
typedef Gp Gp_RCX;
typedef Gp Gp_RDX;

typedef Gp Gp_ZAX;
typedef Gp Gp_ZBX;
typedef Gp Gp_ZCX;
typedef Gp Gp_ZDX;

typedef Mem DS_ZAX; // ds:[zax]
typedef Mem DS_ZDI; // ds:[zdi]
typedef Mem ES_ZDI; // es:[zdi]
typedef Mem DS_ZSI; // ds:[zsi]

typedef Xmm XMM0;
}
}
