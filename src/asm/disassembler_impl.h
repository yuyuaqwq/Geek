#pragma once
#include <geek/asm/disassembler.h>
#include <Zydis/Zydis.h>

namespace geek {
class DisAssembler::Impl {
public:
	Impl(MachineMode machine_mode, StackWidth stack_width, FormatterStyle style);

	std::vector<DisAsmInstruction> DecodeInstructions() const;

	ZydisDecoder decoder_;
	ZydisFormatter formatter_;
	std::vector<uint8_t> code_data_;
	Config config_{};
};
}