#include "assembler_impl.h"

#include <queue>
#include <memory>

#include "utils/debug.h"
#include "asm/assembler/asm_op_defs_impl.h"

namespace geek {
Assembler::Impl::Impl(Assembler* owner, Arch arch, asmjit::JitRuntime* runtime)
	: owner_(owner), runtime_(runtime), arch_(arch)
{
	auto envi = runtime->environment();
	asmjit::Arch a;
	switch (arch)
	{
	case Arch::kX86:
		a = asmjit::Arch::kX86;
		break;
	case Arch::kX64:
		a = asmjit::Arch::kX64;
		break;
	default:
		GEEK_ASSERT(false, "Unknow architecture:", static_cast<uint8_t>(arch));
		return;
	}
	envi.setArch(a);
	code_.init(envi);

	::new(&assembler_) asmjit::x86::Assembler(&code_);
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
		GEEK_ASSERT(false, "Unsupported asmjit error code:", static_cast<uint32_t>(code));
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
		GEEK_ASSERT(false, "Unknow error code:", static_cast<uint32_t>(code));
		return asmjit::kErrorCount;
	}
}

asmjit::LabelType ToAsmJit(asm_op::Label::Type type)
{
	switch (type)
	{
	case asm_op::Label::kAnonymous: return asmjit::LabelType::kAnonymous;
	case asm_op::Label::kLocal: return asmjit::LabelType::kLocal;
	case asm_op::Label::kGlobal: return asmjit::LabelType::kGlobal;
	case asm_op::Label::kExternal: return asmjit::LabelType::kExternal;
	default:
		GEEK_ASSERT(false, "Unknow label type:", static_cast<uint8_t>(type));
		return asmjit::LabelType::kMaxValue;
	}
}

asmjit::Imm ToAsmJit(const asm_op::Imm& imm)
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
	GEEK_ASSERT(false, "Unknow imm type? This assert should not be triggered!");
	return {};
}

asmjit::x86::Mem ToAsmJit(const asm_op::Mem& mem)
{
	return mem.impl_->mem_;
}

const asmjit::x86::Reg& ToAsmJit(const asm_op::Reg& r)
{
	return *r.impl_->reg_;
}

namespace {
	
}

const asmjit::x86::Gp& ToAsmJit(const asm_op::Gp& gp)
{
	GEEK_ASSERT_X(gp.impl_->reg_->isGp());
	return *reinterpret_cast<asmjit::x86::Gp*>(gp.impl_->reg_.get());
}

const asmjit::x86::Vec& ToAsmJit(const asm_op::Vec& gp)
{
	GEEK_ASSERT_X(gp.impl_->reg_->isVec());
	return *reinterpret_cast<asmjit::x86::Vec*>(gp.impl_->reg_.get());
}

const asmjit::x86::CReg& ToAsmJit(const asm_op::CReg& gp)
{
	GEEK_ASSERT_X(gp.impl_->reg_->isCReg());
	return *reinterpret_cast<asmjit::x86::CReg*>(gp.impl_->reg_.get());
}

const asmjit::x86::DReg& ToAsmJit(const asm_op::DReg& gp)
{
	GEEK_ASSERT_X(gp.impl_->reg_->isDReg());
	return *reinterpret_cast<asmjit::x86::DReg*>(gp.impl_->reg_.get());
}

const asmjit::x86::SReg& ToAsmJit(const asm_op::SReg& gp)
{
	GEEK_ASSERT_X(gp.impl_->reg_->isSReg());
	return *reinterpret_cast<asmjit::x86::SReg*>(gp.impl_->reg_.get());
}

const asmjit::x86::Rip& ToAsmJit(const asm_op::Rip& gp)
{
	GEEK_ASSERT_X(gp.impl_->reg_->isRip());
	return *reinterpret_cast<asmjit::x86::Rip*>(gp.impl_->reg_.get());
}

const asmjit::Label& ToAsmJit(const asm_op::Label& label)
{
	return label.impl_->label_;
}
}
