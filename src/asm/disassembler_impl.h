#pragma once
#include <geek/asm/disassembler.h>
#include <Zydis/Zydis.h>

namespace geek {
class DisAssembler::Impl {
public:
	Impl(MachineMode machine_mode, StackWidth stack_width, FormatterStyle style);

	ZydisDecoder decoder_;
	ZydisFormatter formatter_;
};
}