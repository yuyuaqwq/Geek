#include "disassembler_impl.h"

#include <geek/utils/strutil.h>

namespace geek {
DisAssembler::DisAssembler(MachineMode machine_mode, StackWidth stack_width, FormatterStyle style) {
	impl_ = std::make_unique<Impl>(machine_mode, stack_width, style);
}

DisAssembler::~DisAssembler() {}

const std::vector<uint8_t>& DisAssembler::CodeData() const {
	return impl_->code_data_;
}

void DisAssembler::SetCodeData(const std::vector<uint8_t>& buf) {
	impl_->code_data_ = buf;
}

void DisAssembler::SetCodeData(std::vector<uint8_t>&& buf) {
	impl_->code_data_ = std::move(buf);
}

const DisAssembler::Config& DisAssembler::GetConfig() const {
	return impl_->config_;
}
DisAssembler::Config& DisAssembler::GetConfig() {
	return impl_->config_;
}

std::vector<DisAsmInstruction> DisAssembler::DecodeInstructions() const {
	return impl_->DecodeInstructions();
}

DisAsmInstruction::DisAsmInstruction(uint64_t runtime_address, std::string_view instruction)
	: runtime_address_(runtime_address)
	, instruction_(instruction)
{}

std::string DisAsmInstruction::SimpleFormat() const {
	return StrUtil::Combine("0x", std::hex, runtime_address(), ":\t", instruction());
}
}
