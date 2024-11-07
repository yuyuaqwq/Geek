#pragma once
#include <vector>
#include <string>

#include <geek/global.h>

namespace geek {
struct DisAsmConfig {
	uint64_t runtime_address;
};

class DisAsmInstruction;
class DisAssembler {
public:
	enum class MachineMode : uint8_t {
		/**
		 * 64 位长模式。
		 *
		 * 用于现代 x86_64（AMD64/Intel64）架构下的 64 位模式。
		 *
		 * 支持 64 位虚拟地址空间和 64 位寄存器。
		 */
		kLong64,
		/**
		 * 32 位兼容模式，运行在 64 位长模式下的 32 位保护模式。
		 *
		 * 允许 32 位代码在 64 位操作系统中运行。
		 *
		 * 用于支持旧的 32 位应用程序，以兼容 x86_64 系统。
		 */
		kLongCompat32,
		/**
		 * 16 位兼容模式，运行在 64 位长模式下的 16 位保护模式。
		 *
		 * 允许 16 位代码在 64 位环境中执行，通常用于兼容性。
		 */
		kLongCompat16,
		/**
		 * 32 位保护模式。
		 *
		 * 支持 4 GB 的虚拟地址空间和 32 位寄存器。
		 */
		kLegacy32,
		/**
		 * 16 位保护模式。
		 *
		 * 该模式下支持保护性内存访问，但使用 16 位寄存器和段寻址，地址空间较小。
		 */
		kLegacy16,
		/**
		 * 16 位实模式。
		 *
		 * 没有内存保护或虚拟地址空间，仅支持段+偏移的寻址方式，实际寻址能力限制在 1 MB 内存之内。
		 */
		kReal16,
	};

	enum class StackWidth : uint8_t {
		/**
		 * 16 位栈宽。
		 *
		 * 通常用于 16 位模式（如实模式 ZYDIS_MACHINE_MODE_REAL_16 或保护模式 ZYDIS_MACHINE_MODE_LEGACY_16）。
		 *
		 * 栈指针（SP）使用 16 位寄存器表示，栈操作基于 16 位宽度。
		 */
		k16,
		/**
		 * 32 位栈宽。
		 *
		 * 适用于 32 位保护模式（如 ZYDIS_MACHINE_MODE_LEGACY_32）。
		 *
		 * 栈指针（ESP）为 32 位宽度，栈操作基于 32 位宽度。
		 */
		k32,
		/**
		 * 64 位栈宽。
		 *
		 * 用于 64 位长模式（如 ZYDIS_MACHINE_MODE_LONG_64）。
		 *
		 * 栈指针（RSP）为 64 位宽度，栈操作基于 64 位宽度。
		 */
		k64
	};

	enum class FormatterStyle {
		/**
		 * AT&T 风格，源于 Unix 环境。
		 *
		 * 操作数顺序与 Intel 风格相反，从源到目标（例如 mov %ebx, %eax 表示将 ebx 的值复制到 eax 中）。
		 *
		 * 使用 % 前缀来标识寄存器（如 %eax, %ebx）。
		 *
		 * 通常用于 Linux 平台和 GDB 等工具。
		 */
		kATT,
		/**
		 * Intel 风格。
		 *
		 * 操作数顺序从目标到源（例如 mov eax, ebx 表示将 ebx 的值复制到 eax 中）。
		 *
		 * 使用通用的寄存器命名（如 eax, ebx）。
		 *
		 * 常用于 Windows 平台和 IDA、X86Dbg 等工具中。
		 */
		kIntel,
		/**
		 * Microsoft Macro Assembler (MASM) 风格。
		 *
		 * runtime-address 在这个模式被忽略.
		 */
		kIntelMasm,
	};

	DisAssembler(MachineMode machine_mode, StackWidth stack_width, FormatterStyle style = FormatterStyle::kIntel);
	~DisAssembler();

	const std::vector<uint8_t>& CodeBuffer() const;
	void SetCodeBuffer(const std::vector<uint8_t>& buf);
	void SetCodeBuffer(std::vector<uint8_t>&& buf);

	const DisAsmConfig& Config() const;
	DisAsmConfig& Config();

	std::vector<DisAsmInstruction> DecodeInstructions() const;

	_GEEK_IMPL
};

class DisAsmInstruction {
public:
	DisAsmInstruction(uint64_t runtime_address, std::string_view instruction);

	uint64_t runtime_address() const { return runtime_address_; }
	std::string_view instruction() const { return instruction_; }

	std::string SimpleFormat() const;

private:
	uint64_t runtime_address_;
	std::string instruction_;
};
}
