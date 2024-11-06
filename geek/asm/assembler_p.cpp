#include <geek/asm/assembler_p.h>
#include "assembler_p_impl.h"

namespace geek {
namespace internal {
Mem::~Mem()
{
}

Mem::Mem(const Mem& right)
{
	impl_ = std::make_unique<Impl>(*right.impl_);
}

Mem::Mem(Mem&& right) noexcept
{
	impl_ = std::move(right.impl_);
}

Label::~Label()
{
}

Label::Label(const Label& right)
{
	impl_ = std::make_unique<Impl>(*right.impl_);
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

Reg::~Reg()
{
}
}
}
