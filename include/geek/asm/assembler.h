#pragma once
#include <string>
#include <vector>

#include <geek/global.h>
#include <geek/asm/assembler/asm_reg.h>
#include <geek/asm/assembler/asm_op.h>

namespace geek {
namespace internal {
template <class T>
struct FuncTrait {
	static_assert(std::_Always_false<T>, "function only accepts function types as template arguments.");
};
template <class RetT, class... Args>
struct FuncTrait<RetT(Args...)> {
	using Ptr = RetT(*)(Args...);
};
}

class Assembler {
public:
	struct Config {
		bool assert_every_inst = true;
	};

	struct FuncDeleter {
		FuncDeleter() noexcept = default;
		FuncDeleter(const FuncDeleter&) noexcept = default;
		void operator()(void* ptr) const;
	};

	enum ErrorCode : uint32_t;
	class Error;

	Assembler(Arch arch);
	~Assembler();

	Arch GetArch() const;

	const Config& GetConfig() const;
	Config& GetConfig();

	asm_op::Label NewLabel() const;
	asm_op::Label NewNamedLabel(std::string_view name, asm_op::Label::Type type = asm_op::Label::kGlobal) const;
	Error Bind(const asm_op::Label& label) const;

	size_t CodeSize() const;
	const uint8_t* CodeBuffer() const;

	template<class Func>
	auto PackToFunc() const;
	std::vector<uint8_t> PackCode() const;
	size_t CopyCodeTo(uint8_t* ptr, size_t size = static_cast<size_t>(-1)) const;

	_GEEK_ASM_INST_0X(cbw);                                             // ANY       [IMPLICIT] AX      <- Sign Extend AL
	_GEEK_ASM_INST_0X(cdq);                                             // ANY       [IMPLICIT] EDX:EAX <- Sign Extend EAX
	_GEEK_ASM_INST_0X(cdqe);                                           // X64       [IMPLICIT] RAX     <- Sign Extend EAX
	_GEEK_ASM_INST_2X(cmpxchg, Gp, Gp);                             // I486      [IMPLICIT]
	_GEEK_ASM_INST_2X(cmpxchg, Mem, Gp);                            // I486      [IMPLICIT]
	_GEEK_ASM_INST_1X(cmpxchg16b, Mem);                          // CMPXCHG8B [IMPLICIT] m == RDX:RAX ? m <- RCX:RBX
	_GEEK_ASM_INST_1X(cmpxchg8b, Mem);                            // CMPXCHG16B[IMPLICIT] m == EDX:EAX ? m <- ECX:EBX
	_GEEK_ASM_INST_0X(cqo);                                             // X64       [IMPLICIT] RDX:RAX <- Sign Extend RAX
	_GEEK_ASM_INST_0X(cwd);                                             // ANY       [IMPLICIT] DX:AX   <- Sign Extend AX
	_GEEK_ASM_INST_0X(cwde);                                           // ANY       [IMPLICIT] EAX     <- Sign Extend AX
	_GEEK_ASM_INST_1X(div, Gp);                                         // ANY       [IMPLICIT] {AH[Rem]: AL[Quot] <- AX / r8} {xDX[Rem]:xAX[Quot] <- DX:AX / r16|r32|r64}
	_GEEK_ASM_INST_1X(div, Mem);                                        // ANY       [IMPLICIT] {AH[Rem]: AL[Quot] <- AX / m8} {xDX[Rem]:xAX[Quot] <- DX:AX / m16|m32|m64}
	_GEEK_ASM_INST_1X(idiv, Gp);                                       // ANY       [IMPLICIT] {AH[Rem]: AL[Quot] <- AX / r8} {xDX[Rem]:xAX[Quot] <- DX:AX / r16|r32|r64}
	_GEEK_ASM_INST_1X(idiv, Mem);                                      // ANY       [IMPLICIT] {AH[Rem]: AL[Quot] <- AX / m8} {xDX[Rem]:xAX[Quot] <- DX:AX / m16|m32|m64}
	_GEEK_ASM_INST_1X(imul, Gp);                                       // ANY       [IMPLICIT] {AX <- AL * r8} {xAX:xDX <- xAX * r16|r32|r64}
	_GEEK_ASM_INST_1X(imul, Mem);                                      // ANY       [IMPLICIT] {AX <- AL * m8} {xAX:xDX <- xAX * m16|m32|m64}
	_GEEK_ASM_INST_0X(iret);                                           // ANY       [IMPLICIT]
	_GEEK_ASM_INST_0X(iretd);                                         // ANY       [IMPLICIT]
	_GEEK_ASM_INST_0X(iretq);                                         // X64       [IMPLICIT]
	_GEEK_ASM_INST_1X(jecxz, Label);                                  // ANY       [IMPLICIT] Short jump if CX/ECX/RCX is zero.
	_GEEK_ASM_INST_1X(jecxz, Imm);                                    // ANY       [IMPLICIT] Short jump if CX/ECX/RCX is zero.
	_GEEK_ASM_INST_1X(loop, Label);                                    // ANY       [IMPLICIT] Decrement xCX; short jump if xCX != 0.
	_GEEK_ASM_INST_1X(loop, Imm);                                      // ANY       [IMPLICIT] Decrement xCX; short jump if xCX != 0.
	_GEEK_ASM_INST_1X(loope, Label);                                  // ANY       [IMPLICIT] Decrement xCX; short jump if xCX != 0 && ZF == 1.
	_GEEK_ASM_INST_1X(loope, Imm);                                    // ANY       [IMPLICIT] Decrement xCX; short jump if xCX != 0 && ZF == 1.
	_GEEK_ASM_INST_1X(loopne, Label);                                // ANY       [IMPLICIT] Decrement xCX; short jump if xCX != 0 && ZF == 0.
	_GEEK_ASM_INST_1X(loopne, Imm);                                  // ANY       [IMPLICIT] Decrement xCX; short jump if xCX != 0 && ZF == 0.
	_GEEK_ASM_INST_1X(mul, Gp);                                         // ANY       [IMPLICIT] {AX <- AL * r8} {xDX:xAX <- xAX * r16|r32|r64}
	_GEEK_ASM_INST_1X(mul, Mem);                                        // ANY       [IMPLICIT] {AX <- AL * m8} {xDX:xAX <- xAX * m16|m32|m64}
	_GEEK_ASM_INST_0X(ret);
	_GEEK_ASM_INST_1X(ret, Imm);
	_GEEK_ASM_INST_0X(retf);
	_GEEK_ASM_INST_1X(retf, Imm);
	_GEEK_ASM_INST_0X(xlatb);                                         // ANY       [IMPLICIT]

	_GEEK_ASM_INST_2X(adc, Gp, Gp);                                     // ANY
	_GEEK_ASM_INST_2X(adc, Gp, Mem);                                    // ANY
	_GEEK_ASM_INST_2X(adc, Gp, Imm);                                    // ANY
	_GEEK_ASM_INST_2X(adc, Mem, Gp);                                    // ANY
	_GEEK_ASM_INST_2X(adc, Mem, Imm);                                   // ANY
	_GEEK_ASM_INST_2X(add, Gp, Gp);                                     // ANY
	_GEEK_ASM_INST_2X(add, Gp, Mem);                                    // ANY
	_GEEK_ASM_INST_2X(add, Gp, Imm);                                    // ANY
	_GEEK_ASM_INST_2X(add, Mem, Gp);                                    // ANY
	_GEEK_ASM_INST_2X(add, Mem, Imm);                                   // ANY
	_GEEK_ASM_INST_2X(and_, Gp, Gp);                                    // ANY
	_GEEK_ASM_INST_2X(and_, Gp, Mem);                                   // ANY
	_GEEK_ASM_INST_2X(and_, Gp, Imm);                                   // ANY
	_GEEK_ASM_INST_2X(and_, Mem, Gp);                                   // ANY
	_GEEK_ASM_INST_2X(and_, Mem, Imm);                                  // ANY
	_GEEK_ASM_INST_2X(bound, Gp, Mem);									// X86
	_GEEK_ASM_INST_2X(bsf, Gp, Gp);                                     // ANY
	_GEEK_ASM_INST_2X(bsf, Gp, Mem);                                    // ANY
	_GEEK_ASM_INST_2X(bsr, Gp, Gp);                                     // ANY
	_GEEK_ASM_INST_2X(bsr, Gp, Mem);                                    // ANY
	_GEEK_ASM_INST_1X(bswap, Gp);										// ANY
	_GEEK_ASM_INST_2X(bt, Gp, Gp);                                       // ANY
	_GEEK_ASM_INST_2X(bt, Gp, Imm);                                      // ANY
	_GEEK_ASM_INST_2X(bt, Mem, Gp);                                      // ANY
	_GEEK_ASM_INST_2X(bt, Mem, Imm);                                     // ANY
	_GEEK_ASM_INST_2X(btc, Gp, Gp);                                     // ANY
	_GEEK_ASM_INST_2X(btc, Gp, Imm);                                    // ANY
	_GEEK_ASM_INST_2X(btc, Mem, Gp);                                    // ANY
	_GEEK_ASM_INST_2X(btc, Mem, Imm);                                   // ANY
	_GEEK_ASM_INST_2X(btr, Gp, Gp);                                     // ANY
	_GEEK_ASM_INST_2X(btr, Gp, Imm);                                    // ANY
	_GEEK_ASM_INST_2X(btr, Mem, Gp);                                    // ANY
	_GEEK_ASM_INST_2X(btr, Mem, Imm);                                   // ANY
	_GEEK_ASM_INST_2X(bts, Gp, Gp);                                     // ANY
	_GEEK_ASM_INST_2X(bts, Gp, Imm);                                    // ANY
	_GEEK_ASM_INST_2X(bts, Mem, Gp);                                    // ANY
	_GEEK_ASM_INST_2X(bts, Mem, Imm);                                   // ANY
	_GEEK_ASM_INST_1X(cbw, Gp_AX);                                      // ANY [EXPLICIT] AX      <- Sign Extend AL
	_GEEK_ASM_INST_2X(cdq, Gp_EDX, Gp_EAX);                             // ANY [EXPLICIT] EDX:EAX <- Sign Extend EAX
	_GEEK_ASM_INST_1X(cdqe, Gp_EAX);                                   // X64 [EXPLICIT] RAX     <- Sign Extend EAX
	_GEEK_ASM_INST_2X(cqo, Gp_RDX, Gp_RAX);                             // X64 [EXPLICIT] RDX:RAX <- Sign Extend RAX
	_GEEK_ASM_INST_2X(cwd, Gp_DX, Gp_AX);                               // ANY [EXPLICIT] DX:AX   <- Sign Extend AX
	_GEEK_ASM_INST_1X(cwde, Gp_EAX);                                   // ANY [EXPLICIT] EAX     <- Sign Extend AX
	_GEEK_ASM_INST_1X(call, Gp);                                       // ANY
	_GEEK_ASM_INST_1X(call, Mem);                                      // ANY
	_GEEK_ASM_INST_1X(call, Label);                                    // ANY
	_GEEK_ASM_INST_1X(call, Imm);                                      // ANY

	_GEEK_ASM_INST_2X(cmp, Gp, Gp);                                     // ANY
	_GEEK_ASM_INST_2X(cmp, Gp, Mem);                                    // ANY
	_GEEK_ASM_INST_2X(cmp, Gp, Imm);                                    // ANY
	_GEEK_ASM_INST_2X(cmp, Mem, Gp);                                    // ANY
	_GEEK_ASM_INST_2X(cmp, Mem, Imm);                                   // ANY
	_GEEK_ASM_INST_2X(cmps, DS_ZSI, ES_ZDI);                           // ANY [EXPLICIT]

	_GEEK_ASM_INST_1X(dec, Gp);                                         // ANY
	_GEEK_ASM_INST_1X(dec, Mem);                                        // ANY
	_GEEK_ASM_INST_2X(div, Gp, Gp);                                     // ANY [EXPLICIT]  AH[Rem]: AL[Quot] <- AX / r8
	_GEEK_ASM_INST_2X(div, Gp, Mem);                                    // ANY [EXPLICIT]  AH[Rem]: AL[Quot] <- AX / m8
	_GEEK_ASM_INST_3X(div, Gp, Gp, Gp);                                 // ANY [EXPLICIT] xDX[Rem]:xAX[Quot] <- xDX:xAX / r16|r32|r64
	_GEEK_ASM_INST_3X(div, Gp, Gp, Mem);                                // ANY [EXPLICIT] xDX[Rem]:xAX[Quot] <- xDX:xAX / m16|m32|m64
	_GEEK_ASM_INST_2X(idiv, Gp, Gp);                                   // ANY [EXPLICIT]  AH[Rem]: AL[Quot] <- AX / r8
	_GEEK_ASM_INST_2X(idiv, Gp, Mem);                                  // ANY [EXPLICIT]  AH[Rem]: AL[Quot] <- AX / m8
	_GEEK_ASM_INST_3X(idiv, Gp, Gp, Gp);                               // ANY [EXPLICIT] xDX[Rem]:xAX[Quot] <- xDX:xAX / r16|r32|r64
	_GEEK_ASM_INST_3X(idiv, Gp, Gp, Mem);                              // ANY [EXPLICIT] xDX[Rem]:xAX[Quot] <- xDX:xAX / m16|m32|m64
	_GEEK_ASM_INST_2X(imul, Gp, Gp);                                   // ANY [EXPLICIT] AX <- AL * r8 | ra <- ra * rb
	_GEEK_ASM_INST_2X(imul, Gp, Mem);                                  // ANY [EXPLICIT] AX <- AL * m8 | ra <- ra * m16|m32|m64
	_GEEK_ASM_INST_3X(imul, Gp, Gp, Imm);                              // ANY
	_GEEK_ASM_INST_3X(imul, Gp, Mem, Imm);                             // ANY
	_GEEK_ASM_INST_3X(imul, Gp, Gp, Gp);                               // ANY [EXPLICIT] xDX:xAX <- xAX * r16|r32|r64
	_GEEK_ASM_INST_3X(imul, Gp, Gp, Mem);                              // ANY [EXPLICIT] xDX:xAX <- xAX * m16|m32|m64
	_GEEK_ASM_INST_1X(inc, Gp);                                         // ANY
	_GEEK_ASM_INST_1X(inc, Mem);                                        // ANY
	_GEEK_ASM_INST_1C(j, Label);										 // ANY
	_GEEK_ASM_INST_1C(j, Imm);										// ANY
	_GEEK_ASM_INST_2X(jecxz, Gp, Label);                              // ANY [EXPLICIT] Short jump if CX/ECX/RCX is zero.
	_GEEK_ASM_INST_2X(jecxz, Gp, Imm);                                // ANY [EXPLICIT] Short jump if CX/ECX/RCX is zero.
	_GEEK_ASM_INST_1X(jmp, Gp);                                         // ANY
	_GEEK_ASM_INST_1X(jmp, Mem);                                        // ANY
	_GEEK_ASM_INST_1X(jmp, Label);                                      // ANY
	_GEEK_ASM_INST_1X(jmp, Imm);                                        // ANY
	_GEEK_ASM_INST_2X(lcall, Imm, Imm);                               // ANY
	_GEEK_ASM_INST_1X(lcall, Mem);                                    // ANY
	_GEEK_ASM_INST_2X(lea, Gp, Mem);                                    // ANY
	_GEEK_ASM_INST_2X(ljmp, Imm, Imm);                                 // ANY
	_GEEK_ASM_INST_1X(ljmp, Mem);                                      // ANY
	_GEEK_ASM_INST_2X(lods, Gp_ZAX, DS_ZSI);                           // ANY [EXPLICIT]
	_GEEK_ASM_INST_2X(loop, Gp_ZCX, Label);                            // ANY [EXPLICIT] Decrement xCX; short jump if xCX != 0.
	_GEEK_ASM_INST_2X(loop, Gp_ZCX, Imm);                              // ANY [EXPLICIT] Decrement xCX; short jump if xCX != 0.
	_GEEK_ASM_INST_2X(loope, Gp_ZCX, Label);                          // ANY [EXPLICIT] Decrement xCX; short jump if xCX != 0 && ZF == 1.
	_GEEK_ASM_INST_2X(loope, Gp_ZCX, Imm);                            // ANY [EXPLICIT] Decrement xCX; short jump if xCX != 0 && ZF == 1.
	_GEEK_ASM_INST_2X(loopne, Gp_ZCX, Label);                        // ANY [EXPLICIT] Decrement xCX; short jump if xCX != 0 && ZF == 0.
	_GEEK_ASM_INST_2X(loopne, Gp_ZCX, Imm);                          // ANY [EXPLICIT] Decrement xCX; short jump if xCX != 0 && ZF == 0.
	_GEEK_ASM_INST_2X(mov, Gp, Gp);                                     // ANY
	_GEEK_ASM_INST_2X(mov, Gp, Mem);                                    // ANY
	_GEEK_ASM_INST_2X(mov, Gp, Imm);                                    // ANY
	_GEEK_ASM_INST_2X(mov, Mem, Gp);                                    // ANY
	_GEEK_ASM_INST_2X(mov, Mem, Imm);                                   // ANY
	_GEEK_ASM_INST_2X(mov, Gp, CReg);                                   // ANY
	_GEEK_ASM_INST_2X(mov, CReg, Gp);                                   // ANY
	_GEEK_ASM_INST_2X(mov, Gp, DReg);                                   // ANY
	_GEEK_ASM_INST_2X(mov, DReg, Gp);                                   // ANY
	_GEEK_ASM_INST_2X(mov, Gp, SReg);                                   // ANY
	_GEEK_ASM_INST_2X(mov, Mem, SReg);                                  // ANY
	_GEEK_ASM_INST_2X(mov, SReg, Gp);                                   // ANY
	_GEEK_ASM_INST_2X(mov, SReg, Mem);                                  // ANY
	_GEEK_ASM_INST_2X(movabs, Gp, Mem);                              // X64
	_GEEK_ASM_INST_2X(movabs, Gp, Imm);                              // X64
	_GEEK_ASM_INST_2X(movabs, Mem, Gp);                              // X64

	_GEEK_ASM_INST_2X(movs, ES_ZDI, DS_ZSI);                           // ANY [EXPLICIT]
	_GEEK_ASM_INST_2X(movsx, Gp, Gp);                                 // ANY
	_GEEK_ASM_INST_2X(movsx, Gp, Mem);                                // ANY
	_GEEK_ASM_INST_2X(movsxd, Gp, Gp);                               // X64
	_GEEK_ASM_INST_2X(movsxd, Gp, Mem);                              // X64
	_GEEK_ASM_INST_2X(movzx, Gp, Gp);                                 // ANY
	_GEEK_ASM_INST_2X(movzx, Gp, Mem);                                // ANY
	_GEEK_ASM_INST_2X(mul, Gp_AX, Gp);                                  // ANY [EXPLICIT] AX      <-  AL * r8
	_GEEK_ASM_INST_2X(mul, Gp_AX, Mem);                                 // ANY [EXPLICIT] AX      <-  AL * m8
	_GEEK_ASM_INST_3X(mul, Gp_ZDX, Gp_ZAX, Gp);                         // ANY [EXPLICIT] xDX:xAX <- xAX * r16|r32|r64
	_GEEK_ASM_INST_3X(mul, Gp_ZDX, Gp_ZAX, Mem);                        // ANY [EXPLICIT] xDX:xAX <- xAX * m16|m32|m64
	_GEEK_ASM_INST_1X(neg, Gp);                                         // ANY
	_GEEK_ASM_INST_1X(neg, Mem);                                        // ANY
	_GEEK_ASM_INST_0X(nop);                                             // ANY
	_GEEK_ASM_INST_1X(nop, Gp);                                         // ANY
	_GEEK_ASM_INST_1X(nop, Mem);                                        // ANY
	_GEEK_ASM_INST_2X(nop, Gp, Gp);                                     // ANY
	_GEEK_ASM_INST_2X(nop, Mem, Gp);                                    // ANY
	_GEEK_ASM_INST_1X(not_, Gp);                                        // ANY
	_GEEK_ASM_INST_1X(not_, Mem);                                       // ANY
	_GEEK_ASM_INST_2X(or_, Gp, Gp);                                      // ANY
	_GEEK_ASM_INST_2X(or_, Gp, Mem);                                     // ANY
	_GEEK_ASM_INST_2X(or_, Gp, Imm);                                     // ANY
	_GEEK_ASM_INST_2X(or_, Mem, Gp);                                     // ANY
	_GEEK_ASM_INST_2X(or_, Mem, Imm);                                    // ANY
	_GEEK_ASM_INST_1X(pop, Gp);                                         // ANY
	_GEEK_ASM_INST_1X(pop, Mem);                                        // ANY
	_GEEK_ASM_INST_1X(pop, SReg);;                                      // ANY
	_GEEK_ASM_INST_0X(popa);                                           // X86
	_GEEK_ASM_INST_0X(popad);                                         // X86
	_GEEK_ASM_INST_0X(popf);                                           // ANY
	_GEEK_ASM_INST_0X(popfd);                                         // X86
	_GEEK_ASM_INST_0X(popfq);                                         // X64
	_GEEK_ASM_INST_1X(push, Gp);                                       // ANY
	_GEEK_ASM_INST_1X(push, Mem);                                      // ANY
	_GEEK_ASM_INST_1X(push, SReg);                                     // ANY
	_GEEK_ASM_INST_1X(push, Imm);                                      // ANY
	_GEEK_ASM_INST_0X(pusha);                                         // X86
	_GEEK_ASM_INST_0X(pushad);                                       // X86
	_GEEK_ASM_INST_0X(pushf);                                         // ANY
	_GEEK_ASM_INST_0X(pushfd);                                       // X86
	_GEEK_ASM_INST_0X(pushfq);                                       // X64
	_GEEK_ASM_INST_2X(rcl, Gp, Gp_CL);                                  // ANY
	_GEEK_ASM_INST_2X(rcl, Mem, Gp_CL);                                 // ANY
	_GEEK_ASM_INST_2X(rcl, Gp, Imm);                                    // ANY
	_GEEK_ASM_INST_2X(rcl, Mem, Imm);                                   // ANY
	_GEEK_ASM_INST_2X(rcr, Gp, Gp_CL);                                  // ANY
	_GEEK_ASM_INST_2X(rcr, Mem, Gp_CL);                                 // ANY
	_GEEK_ASM_INST_2X(rcr, Gp, Imm);                                    // ANY
	_GEEK_ASM_INST_2X(rcr, Mem, Imm);                                   // ANY
	_GEEK_ASM_INST_2X(rol, Gp, Gp_CL);                                  // ANY
	_GEEK_ASM_INST_2X(rol, Mem, Gp_CL);                                 // ANY
	_GEEK_ASM_INST_2X(rol, Gp, Imm);                                    // ANY
	_GEEK_ASM_INST_2X(rol, Mem, Imm);                                   // ANY
	_GEEK_ASM_INST_2X(ror, Gp, Gp_CL);                                  // ANY
	_GEEK_ASM_INST_2X(ror, Mem, Gp_CL);                                 // ANY
	_GEEK_ASM_INST_2X(ror, Gp, Imm);                                    // ANY
	_GEEK_ASM_INST_2X(ror, Mem, Imm);                                   // ANY
	_GEEK_ASM_INST_2X(sbb, Gp, Gp);                                     // ANY
	_GEEK_ASM_INST_2X(sbb, Gp, Mem);                                    // ANY
	_GEEK_ASM_INST_2X(sbb, Gp, Imm);                                    // ANY
	_GEEK_ASM_INST_2X(sbb, Mem, Gp);                                    // ANY
	_GEEK_ASM_INST_2X(sbb, Mem, Imm);                                   // ANY
	_GEEK_ASM_INST_2X(sal, Gp, Gp_CL);                                  // ANY
	_GEEK_ASM_INST_2X(sal, Mem, Gp_CL);                                 // ANY
	_GEEK_ASM_INST_2X(sal, Gp, Imm);                                    // ANY
	_GEEK_ASM_INST_2X(sal, Mem, Imm);                                   // ANY
	_GEEK_ASM_INST_2X(sar, Gp, Gp_CL);                                  // ANY
	_GEEK_ASM_INST_2X(sar, Mem, Gp_CL);                                 // ANY
	_GEEK_ASM_INST_2X(sar, Gp, Imm);                                    // ANY
	_GEEK_ASM_INST_2X(sar, Mem, Imm);                                   // ANY
	_GEEK_ASM_INST_2X(scas, Gp_ZAX, ES_ZDI);                           // ANY [EXPLICIT]
	_GEEK_ASM_INST_1C(set, Gp);
	_GEEK_ASM_INST_1C(set, Mem);
	_GEEK_ASM_INST_2X(shl, Gp, Gp_CL);                                  // ANY
	_GEEK_ASM_INST_2X(shl, Mem, Gp_CL);                                 // ANY
	_GEEK_ASM_INST_2X(shl, Gp, Imm);                                    // ANY
	_GEEK_ASM_INST_2X(shl, Mem, Imm);                                   // ANY
	_GEEK_ASM_INST_2X(shr, Gp, Gp_CL);                                  // ANY
	_GEEK_ASM_INST_2X(shr, Mem, Gp_CL);                                 // ANY
	_GEEK_ASM_INST_2X(shr, Gp, Imm);                                    // ANY
	_GEEK_ASM_INST_2X(shr, Mem, Imm);                                   // ANY
	_GEEK_ASM_INST_3X(shld, Gp, Gp, Gp_CL);                            // ANY
	_GEEK_ASM_INST_3X(shld, Mem, Gp, Gp_CL);                           // ANY
	_GEEK_ASM_INST_3X(shld, Gp, Gp, Imm);                              // ANY
	_GEEK_ASM_INST_3X(shld, Mem, Gp, Imm);                             // ANY
	_GEEK_ASM_INST_3X(shrd, Gp, Gp, Gp_CL);                            // ANY
	_GEEK_ASM_INST_3X(shrd, Mem, Gp, Gp_CL);                           // ANY
	_GEEK_ASM_INST_3X(shrd, Gp, Gp, Imm);                              // ANY
	_GEEK_ASM_INST_3X(shrd, Mem, Gp, Imm);                             // ANY
	_GEEK_ASM_INST_2X(stos, ES_ZDI, Gp_ZAX);                           // ANY [EXPLICIT]
	_GEEK_ASM_INST_2X(sub, Gp, Gp);                                     // ANY
	_GEEK_ASM_INST_2X(sub, Gp, Mem);                                    // ANY
	_GEEK_ASM_INST_2X(sub, Gp, Imm);                                    // ANY
	_GEEK_ASM_INST_2X(sub, Mem, Gp);                                    // ANY
	_GEEK_ASM_INST_2X(sub, Mem, Imm);                                   // ANY
	_GEEK_ASM_INST_2X(test, Gp, Gp);                                   // ANY
	_GEEK_ASM_INST_2X(test, Gp, Imm);                                  // ANY
	_GEEK_ASM_INST_2X(test, Mem, Gp);                                  // ANY
	_GEEK_ASM_INST_2X(test, Mem, Imm);                                 // ANY
	_GEEK_ASM_INST_2X(ud0, Gp, Gp);                                     // ANY
	_GEEK_ASM_INST_2X(ud0, Gp, Mem);                                    // ANY
	_GEEK_ASM_INST_2X(ud1, Gp, Gp);                                     // ANY
	_GEEK_ASM_INST_2X(ud1, Gp, Mem);                                    // ANY
	_GEEK_ASM_INST_0X(ud2);                                             // ANY
	_GEEK_ASM_INST_2X(xadd, Gp, Gp);                                   // ANY
	_GEEK_ASM_INST_2X(xadd, Mem, Gp);                                  // ANY
	_GEEK_ASM_INST_2X(xchg, Gp, Gp);                                   // ANY
	_GEEK_ASM_INST_2X(xchg, Mem, Gp);                                  // ANY
	_GEEK_ASM_INST_2X(xchg, Gp, Mem);                                  // ANY
	_GEEK_ASM_INST_2X(xor_, Gp, Gp);                                    // ANY
	_GEEK_ASM_INST_2X(xor_, Gp, Mem);                                   // ANY
	_GEEK_ASM_INST_2X(xor_, Gp, Imm);                                   // ANY
	_GEEK_ASM_INST_2X(xor_, Mem, Gp);                                   // ANY
	_GEEK_ASM_INST_2X(xor_, Mem, Imm);                                  // ANY

	//! \name Deprecated 32-bit Instructions
	//! \{

	_GEEK_ASM_INST_1X(aaa, Gp);                                         // X86 [EXPLICIT]
	_GEEK_ASM_INST_2X(aad, Gp, Imm);                                    // X86 [EXPLICIT]
	_GEEK_ASM_INST_2X(aam, Gp, Imm);                                    // X86 [EXPLICIT]
	_GEEK_ASM_INST_1X(aas, Gp);                                         // X86 [EXPLICIT]
	_GEEK_ASM_INST_1X(daa, Gp);                                         // X86 [EXPLICIT]
	_GEEK_ASM_INST_1X(das, Gp);                                         // X86 [EXPLICIT]

	//! \name ENTER/LEAVE Instructions
	//! \{

	_GEEK_ASM_INST_2X(enter, Imm, Imm);                               // ANY
	_GEEK_ASM_INST_0X(leave);                                         // ANY

  //! \name IN/OUT Instructions
  //! \{

  // NOTE: For some reason Doxygen is messed up here and thinks we are in cond.

	_GEEK_ASM_INST_2X(in, Gp_ZAX, Imm);                                  // ANY
	_GEEK_ASM_INST_2X(in, Gp_ZAX, Gp_DX);                                // ANY
	_GEEK_ASM_INST_2X(ins, ES_ZDI, Gp_DX);                              // ANY
	_GEEK_ASM_INST_2X(out, Imm, Gp_ZAX);                                // ANY
	_GEEK_ASM_INST_2X(out, Gp_DX, Gp_ZAX);                              // ANY
	_GEEK_ASM_INST_2X(outs, Gp_DX, DS_ZSI);                            // ANY

	//! \name Clear/Set CF/DF Instructions
	//! \{

	_GEEK_ASM_INST_0X(clc);                                             // ANY
	_GEEK_ASM_INST_0X(cld);                                             // ANY
	_GEEK_ASM_INST_0X(cmc);                                             // ANY
	_GEEK_ASM_INST_0X(stc);                                             // ANY
	_GEEK_ASM_INST_0X(std);                                             // ANY

	Error db(uint8_t x, size_t repeat_count = 1);
	Error dw(uint16_t x, size_t repeat_count = 1);
	Error dd(uint32_t x, size_t repeat_count = 1);
	Error dq(uint64_t x, size_t repeat_count = 1);

private:
	std::unique_ptr<void, FuncDeleter> PackToFuncImpl() const;

	_GEEK_IMPL
};

template <class Func>
auto Assembler::PackToFunc() const {
	auto p = PackToFuncImpl();
	auto ret = std::unique_ptr<Func, FuncDeleter>(reinterpret_cast<Func*>(p.get()));
	p.release();
	return ret;
}

class Assembler::Error {
public:
	Error(ErrorCode code);

	ErrorCode code() const { return code_; }
	std::string msg() const;

	bool IsSuccess() const;

private:
	ErrorCode code_;
};

//! AsmJit error codes.
enum Assembler::ErrorCode : uint32_t {
	//! No error (success).
	kErrorOk = 0,

	//! Out of memory.
	kErrorOutOfMemory,

	//! Invalid argument.
	kErrorInvalidArgument,

	//! Invalid state.
	//!
	//! If this error is returned it means that either you are doing something wrong or AsmJit caught itself by
	//! doing something wrong. This error should never be ignored.
	kErrorInvalidState,

	//! Invalid or incompatible architecture.
	kErrorInvalidArch,

	//! The object is not initialized.
	kErrorNotInitialized,
	//! The object is already initialized.
	kErrorAlreadyInitialized,

	//! Either a built-in feature was disabled at compile time and it's not available or the feature is not
	//! available on the target platform.
	//!
	//! For example trying to allocate large pages on unsupported platform would return this error.
	kErrorFeatureNotEnabled,

	//! Too many handles (Windows) or file descriptors (Unix/Posix).
	kErrorTooManyHandles,
	//! Code generated is larger than allowed.
	kErrorTooLarge,

	//! No code generated.
	//!
	//! Returned by runtime if the \ref CodeHolder contains no code.
	kErrorNoCodeGenerated,

	//! Invalid directive.
	kErrorInvalidDirective,
	//! Attempt to use uninitialized label.
	kErrorInvalidLabel,
	//! Label index overflow - a single \ref BaseAssembler instance can hold almost 2^32 (4 billion) labels. If
	//! there is an attempt to create more labels then this error is returned.
	kErrorTooManyLabels,
	//! Label is already bound.
	kErrorLabelAlreadyBound,
	//! Label is already defined (named labels).
	kErrorLabelAlreadyDefined,
	//! Label name is too long.
	kErrorLabelNameTooLong,
	//! Label must always be local if it's anonymous (without a name).
	kErrorInvalidLabelName,
	//! Parent id passed to \ref CodeHolder::newNamedLabelEntry() was either invalid or parent is not supported
	//! by the requested `LabelType`.
	kErrorInvalidParentLabel,

	//! Invalid section.
	kErrorInvalidSection,
	//! Too many sections (section index overflow).
	kErrorTooManySections,
	//! Invalid section name (most probably too long).
	kErrorInvalidSectionName,

	//! Relocation index overflow (too many relocations).
	kErrorTooManyRelocations,
	//! Invalid relocation entry.
	kErrorInvalidRelocEntry,
	//! Reloc entry contains address that is out of range (unencodable).
	kErrorRelocOffsetOutOfRange,

	//! Invalid assignment to a register, function argument, or function return value.
	kErrorInvalidAssignment,
	//! Invalid instruction.
	kErrorInvalidInstruction,
	//! Invalid register type.
	kErrorInvalidRegType,
	//! Invalid register group.
	kErrorInvalidRegGroup,
	//! Invalid physical register id.
	kErrorInvalidPhysId,
	//! Invalid virtual register id.
	kErrorInvalidVirtId,
	//! Invalid element index (ARM).
	kErrorInvalidElementIndex,
	//! Invalid prefix combination (X86|X64).
	kErrorInvalidPrefixCombination,
	//! Invalid LOCK prefix (X86|X64).
	kErrorInvalidLockPrefix,
	//! Invalid XACQUIRE prefix (X86|X64).
	kErrorInvalidXAcquirePrefix,
	//! Invalid XRELEASE prefix (X86|X64).
	kErrorInvalidXReleasePrefix,
	//! Invalid REP prefix (X86|X64).
	kErrorInvalidRepPrefix,
	//! Invalid REX prefix (X86|X64).
	kErrorInvalidRexPrefix,
	//! Invalid {...} register (X86|X64).
	kErrorInvalidExtraReg,
	//! Invalid {k} use (not supported by the instruction) (X86|X64).
	kErrorInvalidKMaskUse,
	//! Invalid {k}{z} use (not supported by the instruction) (X86|X64).
	kErrorInvalidKZeroUse,
	//! Invalid broadcast - Currently only related to invalid use of AVX-512 {1tox} (X86|X64).
	kErrorInvalidBroadcast,
	//! Invalid 'embedded-rounding' {er} or 'suppress-all-exceptions' {sae} (AVX-512) (X86|X64).
	kErrorInvalidEROrSAE,
	//! Invalid address used (not encodable).
	kErrorInvalidAddress,
	//! Invalid index register used in memory address (not encodable).
	kErrorInvalidAddressIndex,
	//! Invalid address scale (not encodable).
	kErrorInvalidAddressScale,
	//! Invalid use of 64-bit address.
	kErrorInvalidAddress64Bit,
	//! Invalid use of 64-bit address that require 32-bit zero-extension (X64).
	kErrorInvalidAddress64BitZeroExtension,
	//! Invalid displacement (not encodable).
	kErrorInvalidDisplacement,
	//! Invalid segment (X86).
	kErrorInvalidSegment,

	//! Invalid immediate (out of bounds on X86 and invalid pattern on ARM).
	kErrorInvalidImmediate,

	//! Invalid operand size.
	kErrorInvalidOperandSize,
	//! Ambiguous operand size (memory has zero size while it's required to determine the operation type.
	kErrorAmbiguousOperandSize,
	//! Mismatching operand size (size of multiple operands doesn't match the operation size).
	kErrorOperandSizeMismatch,

	//! Invalid option.
	kErrorInvalidOption,
	//! Option already defined.
	kErrorOptionAlreadyDefined,

	//! Invalid TypeId.
	kErrorInvalidTypeId,
	//! Invalid use of a 8-bit GPB-HIGH register.
	kErrorInvalidUseOfGpbHi,
	//! Invalid use of a 64-bit GPQ register in 32-bit mode.
	kErrorInvalidUseOfGpq,
	//! Invalid use of an 80-bit float (\ref TypeId::kFloat80).
	kErrorInvalidUseOfF80,
	//! Instruction requires the use of consecutive registers, but registers in operands weren't (AVX512, ASIMD load/store, etc...).
	kErrorNotConsecutiveRegs,
	//! Failed to allocate consecutive registers - allocable registers either too restricted or a bug in RW info.
	kErrorConsecutiveRegsAllocation,

	//! Illegal virtual register - reported by instruction validation.
	kErrorIllegalVirtReg,
	//! AsmJit cannot create more virtual registers.
	kErrorTooManyVirtRegs,

	//! AsmJit requires a physical register, but no one is available.
	kErrorNoMorePhysRegs,
	//! A variable has been assigned more than once to a function argument (BaseCompiler).
	kErrorOverlappedRegs,
	//! Invalid register to hold stack arguments offset.
	kErrorOverlappingStackRegWithRegArg,

	//! Unbound label cannot be evaluated by expression.
	kErrorExpressionLabelNotBound,
	//! Arithmetic overflow during expression evaluation.
	kErrorExpressionOverflow,

	//! Failed to open anonymous memory handle or file descriptor.
	kErrorFailedToOpenAnonymousMemory,

	//! Failed to open a file.
	//!
	//! \note This is a generic error that is used by internal filesystem API.
	kErrorFailedToOpenFile,

	//! Protection failure can be returned from a virtual memory allocator or when trying to change memory access
	//! permissions.
	kErrorProtectionFailure,

	// @EnumValuesEnd@

	//! Count of AsmJit error codes.
	kErrorCount
};
}
