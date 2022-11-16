#ifndef GEEK_INLINE_HOOK_H_
#define GEEK_INLINE_HOOK_H_

#include <type_traits>

#include <Windows.h>

#include <Process/process.h>
#include <Memory/memory.hpp>

namespace geek {

class InlineHook {
public:
	struct Context {
		uint64_t rax;
		uint64_t rcx;
		uint64_t rdx;
		uint64_t rbx;
		uint64_t rbp;
		uint64_t rsp;
		uint64_t rsi;
		uint64_t rdi;
		uint64_t r8;
		uint64_t r9;
		uint64_t r10;
		uint64_t r11;
		uint64_t r12;
		uint64_t r13;
		uint64_t r14;
		uint64_t r15;
		size_t* stack;
	};
	typedef void (*HookCallBack)(Context* context);

public:
	InlineHook() {

	}
	explicit InlineHook(Process* tProcess = nullptr) : mProcess{ tProcess } {
		
	}
	~InlineHook() noexcept {

	}

public:
	// °²×°Hook
	void Install(LPVOID address, size_t instrLen, HookCallBack callback) {
		auto oldProtect = mProcess->SetProtect(address, instrLen, PAGE_EXECUTE_READWRITE);
		std::vector<char> jmpInstr(instrLen);
		if (mProcess->IsX86()) {
			jmpInstr[0] = 0xe9;
			*(DWORD*)jmpInstr.data() = GetJmpOffset(address, 5, callback);
		}
		else {

		}
		mProcess->WriteMemory(address, jmpInstr.data(), instrLen);
		mProcess->SetProtect(address, instrLen, oldProtect);

	}

	// Ð¶ÔØHook
	void Uninstall() {

	}


private:
	int64_t GetJmpOffset(void* curAddr, size_t instrLen, void* desAddr) {
		size_t curAddr_ = (size_t)curAddr;;
		size_t desAddr_ = (size_t)desAddr;
		return desAddr_ - curAddr_ - instrLen;
	}

private:
	Process* mProcess;
};

} // namespace geek

#endif // GEEK_INLINE_HOOK_H_
