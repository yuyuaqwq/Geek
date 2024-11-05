#include <geek/asm/assembler_p.h>
#include "mem_impl.h"

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
}
}
