#include "asm_op_defs_impl.h"

namespace geek {
namespace asm_op {
Mem::Mem() {}
Mem::~Mem() = default;

Mem::Mem(const Mem& right)
{
	if (right.impl_) {
		impl_ = std::make_unique<Impl>(*right.impl_);
	}
	else {
		impl_.reset();
	}
}

Mem::Mem(Mem&& right) noexcept
{
	impl_ = std::move(right.impl_);
}

Label::Label() {}
Label::~Label() = default;

Label::Label(const Label& right)
{
	if (right.impl_) {
		impl_ = std::make_unique<Impl>(*right.impl_);
	}
	else {
		impl_.reset();
	}
}

Label::Label(Label&& right) noexcept
{
	impl_ = std::move(right.impl_);
}

Reg::Reg(RegisterId id)
	: id_(id)
{
	impl_ = std::make_unique<Impl>(id);
}

Reg::~Reg() = default;
}
}
