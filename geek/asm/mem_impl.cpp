#include "mem_impl.h"

namespace geek {
namespace internal {
Mem::Impl::Impl(asmjit::x86::Mem&& m) 
	: mem_(std::move(m))
{
}
}
}