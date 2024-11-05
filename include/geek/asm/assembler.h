#pragma once
#include <string>

#include <geek/global.h>
#include <geek/asm/assembler_p.h>
#include <geek/asm/regs.h>

namespace geek {
//! Creates `[base.reg + offset]` memory operand.
internal::Mem asm_ptr(regs base, int32_t offset = 0, uint32_t size = 0);
//! Creates `[base.reg + (index << shift) + offset]` memory operand (scalar index).
internal::Mem asm_ptr(regs base, regs index, uint32_t shift = 0, int32_t offset = 0, uint32_t size = 0);

//! Creates `[base]` absolute memory operand.
internal::Mem asm_ptr(uint64_t base, uint32_t size = 0);
//! Creates `[base + (index.reg << shift)]` absolute memory operand.
internal::Mem asm_ptr(uint64_t base, regs index, uint32_t shift = 0, uint32_t size = 0);

class Assembler {
public:
	enum ErrorCode : uint32_t;

	class Error {
	public:
		Error(ErrorCode code);

		ErrorCode code() const noexcept { return code_; }
		std::string msg() const;

	private:
		ErrorCode code_;
	};

	static Assembler Alloc(Arch arch);
	~Assembler();

	Error mov(regs o1, regs o2);
	Error mov(regs o1, const internal::Imm& o2);
	Error mov(regs o1, const internal::Mem& o2);

	Error mov(const internal::Mem& o1, regs o2);
	Error mov(const internal::Mem& o1, const internal::Imm& o2);

private:
	Assembler(Arch arch);

	_GEEK_IMPL
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
