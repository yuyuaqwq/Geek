#include "disassembler_impl.h"

namespace geek {
DisAssembler::DisAssembler(MachineMode machine_mode, StackWidth stack_width, FormatterStyle style) {
	impl_ = std::make_unique<Impl>(machine_mode, stack_width, style);
}
}