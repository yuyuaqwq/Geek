#ifndef GEEK_INLINE_HOOK_H_
#define GEEK_INLINE_HOOK_H_

#include <type_traits>

#include <Windows.h>

#include <Process/process.h>
#include <Memory/memory.hpp>

namespace geek {

class InlineHook {
public:
	InlineHook(void* address, size_t instrLen, Process* t_process) {

	}
	~InlineHook() {

	}


private:

};

} // namespace geek

#endif // GEEK_INLINE_HOOK_H_
