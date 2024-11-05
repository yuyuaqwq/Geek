#include "assembler_impl.h"

#include <queue>
#include <memory>

#include <geek/utils/debug.h>

#include "mem_impl.h"

namespace geek {
Assembler::Impl::Impl(Assembler* owner, Arch arch, asmjit::JitRuntime* runtime)
	: owner_(owner), runtime_(runtime)
{
	auto envi = runtime->environment();
	asmjit::Arch a;
	switch (arch)
	{
	case geek::Arch::kX86:
		a = asmjit::Arch::kX86;
		break;
	case geek::Arch::kX64:
		a = asmjit::Arch::kX64;
		break;
	default:
		throw std::exception("Unsupported architecture");
	};
	envi.setArch(a);
	code_.init(envi);

	::new(&assembler_) asmjit::x86::Assembler(&code_);
}


namespace {
template<class T>
std::unique_ptr<T, RegDeleter> AllocReg(const T& copy)
{
	static std::queue<T*> pool;

	// 如果池为空，就new一个新对象；否则就从池中取
	T* p;
	if (pool.empty()) {
		p = new T();
	}
	else {
		p = pool.front();
		pool.pop();
	}
	// 调用拷贝构造
	::new(p) T(copy);
	auto d = RegDeleter();

	// 定义删除器
	d.deleter = [](void* ptr) {
		pool.push(reinterpret_cast<T*>(ptr));
		};
	return std::unique_ptr<T, RegDeleter>(p, std::move(d));
}
}

#define REG2ASMJIT(r) \
case regs::r: \
	return AllocReg(asmjit::x86::r)

std::unique_ptr<asmjit::x86::Reg, RegDeleter> ToAsmJit(regs r)
{
	switch (r)
	{
		REG2ASMJIT(al);
		REG2ASMJIT(bl);
		REG2ASMJIT(cl);
		REG2ASMJIT(dl);
		REG2ASMJIT(spl);
		REG2ASMJIT(bpl);
		REG2ASMJIT(sil);
		REG2ASMJIT(dil);
		REG2ASMJIT(r8b);
		REG2ASMJIT(r9b);
		REG2ASMJIT(r10b);
		REG2ASMJIT(r11b);
		REG2ASMJIT(r12b);
		REG2ASMJIT(r13b);
		REG2ASMJIT(r14b);
		REG2ASMJIT(r15b);

		REG2ASMJIT(ah);
		REG2ASMJIT(bh);
		REG2ASMJIT(ch);
		REG2ASMJIT(dh);

		REG2ASMJIT(ax);
		REG2ASMJIT(bx);
		REG2ASMJIT(cx);
		REG2ASMJIT(dx);
		REG2ASMJIT(sp);
		REG2ASMJIT(bp);
		REG2ASMJIT(si);
		REG2ASMJIT(di);
		REG2ASMJIT(r8w);
		REG2ASMJIT(r9w);
		REG2ASMJIT(r10w);
		REG2ASMJIT(r11w);
		REG2ASMJIT(r12w);
		REG2ASMJIT(r13w);
		REG2ASMJIT(r14w);
		REG2ASMJIT(r15w);

		REG2ASMJIT(eax);
		REG2ASMJIT(ebx);
		REG2ASMJIT(ecx);
		REG2ASMJIT(edx);
		REG2ASMJIT(esp);
		REG2ASMJIT(ebp);
		REG2ASMJIT(esi);
		REG2ASMJIT(edi);
		REG2ASMJIT(r8d);
		REG2ASMJIT(r9d);
		REG2ASMJIT(r10d);
		REG2ASMJIT(r11d);
		REG2ASMJIT(r12d);
		REG2ASMJIT(r13d);
		REG2ASMJIT(r14d);
		REG2ASMJIT(r15d);

		REG2ASMJIT(rax);
		REG2ASMJIT(rbx);
		REG2ASMJIT(rcx);
		REG2ASMJIT(rdx);
		REG2ASMJIT(rsp);
		REG2ASMJIT(rbp);
		REG2ASMJIT(rsi);
		REG2ASMJIT(rdi);
		REG2ASMJIT(r8);
		REG2ASMJIT(r9);
		REG2ASMJIT(r10);
		REG2ASMJIT(r11);
		REG2ASMJIT(r12);
		REG2ASMJIT(r13);
		REG2ASMJIT(r14);
		REG2ASMJIT(r15);

		REG2ASMJIT(xmm0);
		REG2ASMJIT(xmm1);
		REG2ASMJIT(xmm2);
		REG2ASMJIT(xmm3);
		REG2ASMJIT(xmm4);
		REG2ASMJIT(xmm5);
		REG2ASMJIT(xmm6);
		REG2ASMJIT(xmm7);
		REG2ASMJIT(xmm8);
		REG2ASMJIT(xmm9);
		REG2ASMJIT(xmm10);
		REG2ASMJIT(xmm11);
		REG2ASMJIT(xmm12);
		REG2ASMJIT(xmm13);
		REG2ASMJIT(xmm14);
		REG2ASMJIT(xmm15);
		REG2ASMJIT(xmm16);
		REG2ASMJIT(xmm17);
		REG2ASMJIT(xmm18);
		REG2ASMJIT(xmm19);
		REG2ASMJIT(xmm20);
		REG2ASMJIT(xmm21);
		REG2ASMJIT(xmm22);
		REG2ASMJIT(xmm23);
		REG2ASMJIT(xmm24);
		REG2ASMJIT(xmm25);
		REG2ASMJIT(xmm26);
		REG2ASMJIT(xmm27);
		REG2ASMJIT(xmm28);
		REG2ASMJIT(xmm29);
		REG2ASMJIT(xmm30);
		REG2ASMJIT(xmm31);

		REG2ASMJIT(ymm0);
		REG2ASMJIT(ymm1);
		REG2ASMJIT(ymm2);
		REG2ASMJIT(ymm3);
		REG2ASMJIT(ymm4);
		REG2ASMJIT(ymm5);
		REG2ASMJIT(ymm6);
		REG2ASMJIT(ymm7);
		REG2ASMJIT(ymm8);
		REG2ASMJIT(ymm9);
		REG2ASMJIT(ymm10);
		REG2ASMJIT(ymm11);
		REG2ASMJIT(ymm12);
		REG2ASMJIT(ymm13);
		REG2ASMJIT(ymm14);
		REG2ASMJIT(ymm15);
		REG2ASMJIT(ymm16);
		REG2ASMJIT(ymm17);
		REG2ASMJIT(ymm18);
		REG2ASMJIT(ymm19);
		REG2ASMJIT(ymm20);
		REG2ASMJIT(ymm21);
		REG2ASMJIT(ymm22);
		REG2ASMJIT(ymm23);
		REG2ASMJIT(ymm24);
		REG2ASMJIT(ymm25);
		REG2ASMJIT(ymm26);
		REG2ASMJIT(ymm27);
		REG2ASMJIT(ymm28);
		REG2ASMJIT(ymm29);
		REG2ASMJIT(ymm30);
		REG2ASMJIT(ymm31);

		REG2ASMJIT(zmm0);
		REG2ASMJIT(zmm1);
		REG2ASMJIT(zmm2);
		REG2ASMJIT(zmm3);
		REG2ASMJIT(zmm4);
		REG2ASMJIT(zmm5);
		REG2ASMJIT(zmm6);
		REG2ASMJIT(zmm7);
		REG2ASMJIT(zmm8);
		REG2ASMJIT(zmm9);
		REG2ASMJIT(zmm10);
		REG2ASMJIT(zmm11);
		REG2ASMJIT(zmm12);
		REG2ASMJIT(zmm13);
		REG2ASMJIT(zmm14);
		REG2ASMJIT(zmm15);
		REG2ASMJIT(zmm16);
		REG2ASMJIT(zmm17);
		REG2ASMJIT(zmm18);
		REG2ASMJIT(zmm19);
		REG2ASMJIT(zmm20);
		REG2ASMJIT(zmm21);
		REG2ASMJIT(zmm22);
		REG2ASMJIT(zmm23);
		REG2ASMJIT(zmm24);
		REG2ASMJIT(zmm25);
		REG2ASMJIT(zmm26);
		REG2ASMJIT(zmm27);
		REG2ASMJIT(zmm28);
		REG2ASMJIT(zmm29);
		REG2ASMJIT(zmm30);
		REG2ASMJIT(zmm31);

		REG2ASMJIT(mm0);
		REG2ASMJIT(mm1);
		REG2ASMJIT(mm2);
		REG2ASMJIT(mm3);
		REG2ASMJIT(mm4);
		REG2ASMJIT(mm5);
		REG2ASMJIT(mm6);
		REG2ASMJIT(mm7);

		REG2ASMJIT(k0);
		REG2ASMJIT(k1);
		REG2ASMJIT(k2);
		REG2ASMJIT(k3);
		REG2ASMJIT(k4);
		REG2ASMJIT(k5);
		REG2ASMJIT(k6);
		REG2ASMJIT(k7);

		REG2ASMJIT(no_seg);
		REG2ASMJIT(es);
		REG2ASMJIT(cs);
		REG2ASMJIT(ss);
		REG2ASMJIT(ds);
		REG2ASMJIT(fs);
		REG2ASMJIT(gs);

		REG2ASMJIT(cr0);
		REG2ASMJIT(cr1);
		REG2ASMJIT(cr2);
		REG2ASMJIT(cr3);
		REG2ASMJIT(cr4);
		REG2ASMJIT(cr5);
		REG2ASMJIT(cr6);
		REG2ASMJIT(cr7);
		REG2ASMJIT(cr8);
		REG2ASMJIT(cr9);
		REG2ASMJIT(cr10);
		REG2ASMJIT(cr11);
		REG2ASMJIT(cr12);
		REG2ASMJIT(cr13);
		REG2ASMJIT(cr14);
		REG2ASMJIT(cr15);

		REG2ASMJIT(dr0);
		REG2ASMJIT(dr1);
		REG2ASMJIT(dr2);
		REG2ASMJIT(dr3);
		REG2ASMJIT(dr4);
		REG2ASMJIT(dr5);
		REG2ASMJIT(dr6);
		REG2ASMJIT(dr7);
		REG2ASMJIT(dr8);
		REG2ASMJIT(dr9);
		REG2ASMJIT(dr10);
		REG2ASMJIT(dr11);
		REG2ASMJIT(dr12);
		REG2ASMJIT(dr13);
		REG2ASMJIT(dr14);
		REG2ASMJIT(dr15);

		REG2ASMJIT(st0);
		REG2ASMJIT(st1);
		REG2ASMJIT(st2);
		REG2ASMJIT(st3);
		REG2ASMJIT(st4);
		REG2ASMJIT(st5);
		REG2ASMJIT(st6);
		REG2ASMJIT(st7);

		REG2ASMJIT(bnd0);
		REG2ASMJIT(bnd1);
		REG2ASMJIT(bnd2);
		REG2ASMJIT(bnd3);

		REG2ASMJIT(tmm0);
		REG2ASMJIT(tmm1);
		REG2ASMJIT(tmm2);
		REG2ASMJIT(tmm3);
		REG2ASMJIT(tmm4);
		REG2ASMJIT(tmm5);
		REG2ASMJIT(tmm6);
		REG2ASMJIT(tmm7);

		REG2ASMJIT(rip);
	default:
		throw std::exception("This register cannot be converted to asmjit::x86::Gp");
	}
}

Assembler::ErrorCode FromAsmJit(asmjit::ErrorCode code) noexcept
{
	switch (code)
	{
	case asmjit::ErrorCode::kErrorOk: return Assembler::kErrorOk;
	case asmjit::ErrorCode::kErrorOutOfMemory: return Assembler::kErrorOutOfMemory;
	case asmjit::ErrorCode::kErrorInvalidArgument: return Assembler::kErrorInvalidArgument;
	case asmjit::ErrorCode::kErrorInvalidState: return Assembler::kErrorInvalidState;
	case asmjit::ErrorCode::kErrorInvalidArch: return Assembler::kErrorInvalidArch;
	case asmjit::ErrorCode::kErrorNotInitialized: return Assembler::kErrorNotInitialized;
	case asmjit::ErrorCode::kErrorAlreadyInitialized: return Assembler::kErrorAlreadyInitialized;
	case asmjit::ErrorCode::kErrorFeatureNotEnabled: return Assembler::kErrorFeatureNotEnabled;
	case asmjit::ErrorCode::kErrorTooManyHandles: return Assembler::kErrorTooManyHandles;
	case asmjit::ErrorCode::kErrorTooLarge: return Assembler::kErrorTooLarge;
	case asmjit::ErrorCode::kErrorNoCodeGenerated: return Assembler::kErrorNoCodeGenerated;
	case asmjit::ErrorCode::kErrorInvalidDirective: return Assembler::kErrorInvalidDirective;
	case asmjit::ErrorCode::kErrorInvalidLabel: return Assembler::kErrorInvalidLabel;
	case asmjit::ErrorCode::kErrorTooManyLabels: return Assembler::kErrorTooManyLabels;
	case asmjit::ErrorCode::kErrorLabelAlreadyBound: return Assembler::kErrorLabelAlreadyBound;
	case asmjit::ErrorCode::kErrorLabelAlreadyDefined: return Assembler::kErrorLabelAlreadyDefined;
	case asmjit::ErrorCode::kErrorLabelNameTooLong: return Assembler::kErrorLabelNameTooLong;
	case asmjit::ErrorCode::kErrorInvalidLabelName: return Assembler::kErrorInvalidLabelName;
	case asmjit::ErrorCode::kErrorInvalidParentLabel: return Assembler::kErrorInvalidParentLabel;
	case asmjit::ErrorCode::kErrorInvalidSection: return Assembler::kErrorInvalidSection;
	case asmjit::ErrorCode::kErrorTooManySections: return Assembler::kErrorTooManySections;
	case asmjit::ErrorCode::kErrorInvalidSectionName: return Assembler::kErrorInvalidSectionName;
	case asmjit::ErrorCode::kErrorTooManyRelocations: return Assembler::kErrorTooManyRelocations;
	case asmjit::ErrorCode::kErrorInvalidRelocEntry: return Assembler::kErrorInvalidRelocEntry;
	case asmjit::ErrorCode::kErrorRelocOffsetOutOfRange: return Assembler::kErrorRelocOffsetOutOfRange;
	case asmjit::ErrorCode::kErrorInvalidAssignment: return Assembler::kErrorInvalidAssignment;
	case asmjit::ErrorCode::kErrorInvalidInstruction: return Assembler::kErrorInvalidInstruction;
	case asmjit::ErrorCode::kErrorInvalidRegType: return Assembler::kErrorInvalidRegType;
	case asmjit::ErrorCode::kErrorInvalidRegGroup: return Assembler::kErrorInvalidRegGroup;
	case asmjit::ErrorCode::kErrorInvalidPhysId: return Assembler::kErrorInvalidPhysId;
	case asmjit::ErrorCode::kErrorInvalidVirtId: return Assembler::kErrorInvalidVirtId;
	case asmjit::ErrorCode::kErrorInvalidElementIndex: return Assembler::kErrorInvalidElementIndex;
	case asmjit::ErrorCode::kErrorInvalidPrefixCombination: return Assembler::kErrorInvalidPrefixCombination;
	case asmjit::ErrorCode::kErrorInvalidLockPrefix: return Assembler::kErrorInvalidLockPrefix;
	case asmjit::ErrorCode::kErrorInvalidXAcquirePrefix: return Assembler::kErrorInvalidXAcquirePrefix;
	case asmjit::ErrorCode::kErrorInvalidXReleasePrefix: return Assembler::kErrorInvalidXReleasePrefix;
	case asmjit::ErrorCode::kErrorInvalidRepPrefix: return Assembler::kErrorInvalidRepPrefix;
	case asmjit::ErrorCode::kErrorInvalidRexPrefix: return Assembler::kErrorInvalidRexPrefix;
	case asmjit::ErrorCode::kErrorInvalidExtraReg: return Assembler::kErrorInvalidExtraReg;
	case asmjit::ErrorCode::kErrorInvalidKMaskUse: return Assembler::kErrorInvalidKMaskUse;
	case asmjit::ErrorCode::kErrorInvalidKZeroUse: return Assembler::kErrorInvalidKZeroUse;
	case asmjit::ErrorCode::kErrorInvalidBroadcast: return Assembler::kErrorInvalidBroadcast;
	case asmjit::ErrorCode::kErrorInvalidEROrSAE: return Assembler::kErrorInvalidEROrSAE;
	case asmjit::ErrorCode::kErrorInvalidAddress: return Assembler::kErrorInvalidAddress;
	case asmjit::ErrorCode::kErrorInvalidAddressIndex: return Assembler::kErrorInvalidAddressIndex;
	case asmjit::ErrorCode::kErrorInvalidAddressScale: return Assembler::kErrorInvalidAddressScale;
	case asmjit::ErrorCode::kErrorInvalidAddress64Bit: return Assembler::kErrorInvalidAddress64Bit;
	case asmjit::ErrorCode::kErrorInvalidAddress64BitZeroExtension: return Assembler::kErrorInvalidAddress64BitZeroExtension;
	case asmjit::ErrorCode::kErrorInvalidDisplacement: return Assembler::kErrorInvalidDisplacement;
	case asmjit::ErrorCode::kErrorInvalidSegment: return Assembler::kErrorInvalidSegment;
	case asmjit::ErrorCode::kErrorInvalidImmediate: return Assembler::kErrorInvalidImmediate;
	case asmjit::ErrorCode::kErrorInvalidOperandSize: return Assembler::kErrorInvalidOperandSize;
	case asmjit::ErrorCode::kErrorAmbiguousOperandSize: return Assembler::kErrorAmbiguousOperandSize;
	case asmjit::ErrorCode::kErrorOperandSizeMismatch: return Assembler::kErrorOperandSizeMismatch;
	case asmjit::ErrorCode::kErrorInvalidOption: return Assembler::kErrorInvalidOption;
	case asmjit::ErrorCode::kErrorOptionAlreadyDefined: return Assembler::kErrorOptionAlreadyDefined;
	case asmjit::ErrorCode::kErrorInvalidTypeId: return Assembler::kErrorInvalidTypeId;
	case asmjit::ErrorCode::kErrorInvalidUseOfGpbHi: return Assembler::kErrorInvalidUseOfGpbHi;
	case asmjit::ErrorCode::kErrorInvalidUseOfGpq: return Assembler::kErrorInvalidUseOfGpq;
	case asmjit::ErrorCode::kErrorInvalidUseOfF80: return Assembler::kErrorInvalidUseOfF80;
	case asmjit::ErrorCode::kErrorNotConsecutiveRegs: return Assembler::kErrorNotConsecutiveRegs;
	case asmjit::ErrorCode::kErrorConsecutiveRegsAllocation: return Assembler::kErrorConsecutiveRegsAllocation;
	case asmjit::ErrorCode::kErrorIllegalVirtReg: return Assembler::kErrorIllegalVirtReg;
	case asmjit::ErrorCode::kErrorTooManyVirtRegs: return Assembler::kErrorTooManyVirtRegs;
	case asmjit::ErrorCode::kErrorNoMorePhysRegs: return Assembler::kErrorNoMorePhysRegs;
	case asmjit::ErrorCode::kErrorOverlappedRegs: return Assembler::kErrorOverlappedRegs;
	case asmjit::ErrorCode::kErrorOverlappingStackRegWithRegArg: return Assembler::kErrorOverlappingStackRegWithRegArg;
	case asmjit::ErrorCode::kErrorExpressionLabelNotBound: return Assembler::kErrorExpressionLabelNotBound;
	case asmjit::ErrorCode::kErrorExpressionOverflow: return Assembler::kErrorExpressionOverflow;
	case asmjit::ErrorCode::kErrorFailedToOpenAnonymousMemory: return Assembler::kErrorFailedToOpenAnonymousMemory;
	case asmjit::ErrorCode::kErrorFailedToOpenFile: return Assembler::kErrorFailedToOpenFile;
	case asmjit::ErrorCode::kErrorProtectionFailure: return Assembler::kErrorProtectionFailure;
	default:
		GEEK_ASSERT_(false, L"Unsupported asmjit error code!");
		return Assembler::kErrorCount;
	}
}

asmjit::ErrorCode ToAsmJit(Assembler::ErrorCode code) noexcept
{
	switch (code)
	{
	case Assembler::kErrorOk: return asmjit::kErrorOk;
	case Assembler::kErrorOutOfMemory: return asmjit::kErrorOutOfMemory;
	case Assembler::kErrorInvalidArgument: return asmjit::kErrorInvalidArgument;
	case Assembler::kErrorInvalidState: return asmjit::kErrorInvalidState;
	case Assembler::kErrorInvalidArch: return asmjit::kErrorInvalidArch;
	case Assembler::kErrorNotInitialized: return asmjit::kErrorNotInitialized;
	case Assembler::kErrorAlreadyInitialized: return asmjit::kErrorAlreadyInitialized;
	case Assembler::kErrorFeatureNotEnabled: return asmjit::kErrorFeatureNotEnabled;
	case Assembler::kErrorTooManyHandles: return asmjit::kErrorTooManyHandles;
	case Assembler::kErrorTooLarge: return asmjit::kErrorTooLarge;
	case Assembler::kErrorNoCodeGenerated: return asmjit::kErrorNoCodeGenerated;
	case Assembler::kErrorInvalidDirective: return asmjit::kErrorInvalidDirective;
	case Assembler::kErrorInvalidLabel: return asmjit::kErrorInvalidLabel;
	case Assembler::kErrorTooManyLabels: return asmjit::kErrorTooManyLabels;
	case Assembler::kErrorLabelAlreadyBound: return asmjit::kErrorLabelAlreadyBound;
	case Assembler::kErrorLabelAlreadyDefined: return asmjit::kErrorLabelAlreadyDefined;
	case Assembler::kErrorLabelNameTooLong: return asmjit::kErrorLabelNameTooLong;
	case Assembler::kErrorInvalidLabelName: return asmjit::kErrorInvalidLabelName;
	case Assembler::kErrorInvalidParentLabel: return asmjit::kErrorInvalidParentLabel;
	case Assembler::kErrorInvalidSection: return asmjit::kErrorInvalidSection;
	case Assembler::kErrorTooManySections: return asmjit::kErrorTooManySections;
	case Assembler::kErrorInvalidSectionName: return asmjit::kErrorInvalidSectionName;
	case Assembler::kErrorTooManyRelocations: return asmjit::kErrorTooManyRelocations;
	case Assembler::kErrorInvalidRelocEntry: return asmjit::kErrorInvalidRelocEntry;
	case Assembler::kErrorRelocOffsetOutOfRange: return asmjit::kErrorRelocOffsetOutOfRange;
	case Assembler::kErrorInvalidAssignment: return asmjit::kErrorInvalidAssignment;
	case Assembler::kErrorInvalidInstruction: return asmjit::kErrorInvalidInstruction;
	case Assembler::kErrorInvalidRegType: return asmjit::kErrorInvalidRegType;
	case Assembler::kErrorInvalidRegGroup: return asmjit::kErrorInvalidRegGroup;
	case Assembler::kErrorInvalidPhysId: return asmjit::kErrorInvalidPhysId;
	case Assembler::kErrorInvalidVirtId: return asmjit::kErrorInvalidVirtId;
	case Assembler::kErrorInvalidElementIndex: return asmjit::kErrorInvalidElementIndex;
	case Assembler::kErrorInvalidPrefixCombination: return asmjit::kErrorInvalidPrefixCombination;
	case Assembler::kErrorInvalidLockPrefix: return asmjit::kErrorInvalidLockPrefix;
	case Assembler::kErrorInvalidXAcquirePrefix: return asmjit::kErrorInvalidXAcquirePrefix;
	case Assembler::kErrorInvalidXReleasePrefix: return asmjit::kErrorInvalidXReleasePrefix;
	case Assembler::kErrorInvalidRepPrefix: return asmjit::kErrorInvalidRepPrefix;
	case Assembler::kErrorInvalidRexPrefix: return asmjit::kErrorInvalidRexPrefix;
	case Assembler::kErrorInvalidExtraReg: return asmjit::kErrorInvalidExtraReg;
	case Assembler::kErrorInvalidKMaskUse: return asmjit::kErrorInvalidKMaskUse;
	case Assembler::kErrorInvalidKZeroUse: return asmjit::kErrorInvalidKZeroUse;
	case Assembler::kErrorInvalidBroadcast: return asmjit::kErrorInvalidBroadcast;
	case Assembler::kErrorInvalidEROrSAE: return asmjit::kErrorInvalidEROrSAE;
	case Assembler::kErrorInvalidAddress: return asmjit::kErrorInvalidAddress;
	case Assembler::kErrorInvalidAddressIndex: return asmjit::kErrorInvalidAddressIndex;
	case Assembler::kErrorInvalidAddressScale: return asmjit::kErrorInvalidAddressScale;
	case Assembler::kErrorInvalidAddress64Bit: return asmjit::kErrorInvalidAddress64Bit;
	case Assembler::kErrorInvalidAddress64BitZeroExtension: return asmjit::kErrorInvalidAddress64BitZeroExtension;
	case Assembler::kErrorInvalidDisplacement: return asmjit::kErrorInvalidDisplacement;
	case Assembler::kErrorInvalidSegment: return asmjit::kErrorInvalidSegment;
	case Assembler::kErrorInvalidImmediate: return asmjit::kErrorInvalidImmediate;
	case Assembler::kErrorInvalidOperandSize: return asmjit::kErrorInvalidOperandSize;
	case Assembler::kErrorAmbiguousOperandSize: return asmjit::kErrorAmbiguousOperandSize;
	case Assembler::kErrorOperandSizeMismatch: return asmjit::kErrorOperandSizeMismatch;
	case Assembler::kErrorInvalidOption: return asmjit::kErrorInvalidOption;
	case Assembler::kErrorOptionAlreadyDefined: return asmjit::kErrorOptionAlreadyDefined;
	case Assembler::kErrorInvalidTypeId: return asmjit::kErrorInvalidTypeId;
	case Assembler::kErrorInvalidUseOfGpbHi: return asmjit::kErrorInvalidUseOfGpbHi;
	case Assembler::kErrorInvalidUseOfGpq: return asmjit::kErrorInvalidUseOfGpq;
	case Assembler::kErrorInvalidUseOfF80: return asmjit::kErrorInvalidUseOfF80;
	case Assembler::kErrorNotConsecutiveRegs: return asmjit::kErrorNotConsecutiveRegs;
	case Assembler::kErrorConsecutiveRegsAllocation: return asmjit::kErrorConsecutiveRegsAllocation;
	case Assembler::kErrorIllegalVirtReg: return asmjit::kErrorIllegalVirtReg;
	case Assembler::kErrorTooManyVirtRegs: return asmjit::kErrorTooManyVirtRegs;
	case Assembler::kErrorNoMorePhysRegs: return asmjit::kErrorNoMorePhysRegs;
	case Assembler::kErrorOverlappedRegs: return asmjit::kErrorOverlappedRegs;
	case Assembler::kErrorOverlappingStackRegWithRegArg: return asmjit::kErrorOverlappingStackRegWithRegArg;
	case Assembler::kErrorExpressionLabelNotBound: return asmjit::kErrorExpressionLabelNotBound;
	case Assembler::kErrorExpressionOverflow: return asmjit::kErrorExpressionOverflow;
	case Assembler::kErrorFailedToOpenAnonymousMemory: return asmjit::kErrorFailedToOpenAnonymousMemory;
	case Assembler::kErrorFailedToOpenFile: return asmjit::kErrorFailedToOpenFile;
	case Assembler::kErrorProtectionFailure: return asmjit::kErrorProtectionFailure;
	default:
		GEEK_ASSERT(false);
		return asmjit::kErrorCount;
	}
}

asmjit::Imm ToAsmJit(const internal::Imm& imm)
{
	if (imm.is_integral()) {
		return imm.integral();
	}
	if (imm.is_float()) {
		return imm.float_();
	}
	if (imm.is_double()) {
		return imm.double_();
	}
	GEEK_ASSERT(false);
	return {};
}

asmjit::x86::Mem ToAsmJit(const internal::Mem& mem)
{
	return mem.impl_->mem_;
}

namespace {
template<class T, class E, class D>
std::unique_ptr<T, D> UniquePtrCast(std::unique_ptr<E, D>&& ptr) {
	auto p = reinterpret_cast<T*>(ptr.get());
	auto d = std::move(ptr.get_deleter());
	GEEK_ASSERT(p != nullptr);
	ptr.release();
	return std::unique_ptr<T, D>(p, std::move(d));
}
}

#define TO_ASMJIT_REG_IMPL(x)											\
std::unique_ptr<asmjit::x86::x, RegDeleter> ToAsmJit##x(regs r) {	\
	auto reg = ToAsmJit(r);											\
	if (!reg->is##x())												\
		return nullptr;												\
	return UniquePtrCast<asmjit::x86::x>(std::move(reg));	\
}

TO_ASMJIT_REG_IMPL(Gp)
TO_ASMJIT_REG_IMPL(Vec)
TO_ASMJIT_REG_IMPL(Rip)
}
