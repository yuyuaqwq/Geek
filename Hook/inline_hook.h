#ifndef GEEK_INLINE_HOOK_H_
#define GEEK_INLINE_HOOK_H_

#include <type_traits>

#include <Windows.h>

#include <Process/process.h>


namespace geek {

class InlineHook {
public:

	struct Context {
#ifdef _WIN64
		uint64_t rflags;
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
#else
		uint32_t eflags;
		uint32_t edi;
		uint32_t esi;
		uint32_t ebp;
		uint32_t esp;
		uint32_t ebx;
		uint32_t edx;
		uint32_t ecx;
		uint32_t eax;
#endif
		size_t stack[];
	};
	typedef void (*HookCallBack)(Context* context);

public:
	explicit InlineHook(Process* tProcess = nullptr) : mProcess{ tProcess }, mHookAddr{ nullptr }, mJmpAddr{ nullptr }, mforwardPage{ nullptr }{
		
	}
	~InlineHook() noexcept {

	}

public:

	// 安装Hook
	// 被hook处用于覆写的指令不能存在相对偏移指令，如0xe8、0xe9
	bool Install(void* hookAddr, size_t instrLen, HookCallBack callback) {
		mforwardPage = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!mforwardPage) {
			return false;
		}
		
		// 保存原指令
		mOldInstr.resize(instrLen);
		memcpy(mOldInstr.data(), hookAddr, instrLen);

		auto oldProtect = mProcess->SetProtect(hookAddr, instrLen, PAGE_EXECUTE_READWRITE);
		std::vector<char> jmpInstr(instrLen);
		if (mProcess->IsX86()) {
			if (instrLen < 5) {
				return false;
			}

			// 处理转发页面指令
			auto forwardPage = (char*)mforwardPage;
			int i = 0;

			forwardPage[i++] = 0x60;		// pushad
			forwardPage[i++] = 0x9c;		// pushfd

			forwardPage[i++] = 0x54;		// push esp

			forwardPage[i++] = 0xe8;		// call
			*(DWORD*)&forwardPage[i] = GetJmpOffset(forwardPage + i - 1, 5, callback);
			i += 4;

			forwardPage[i++] = 0x5c;		// pop esp

			forwardPage[i++] = 0x9d;		// popfd
			forwardPage[i++] = 0x61;		// popad

			memcpy(&forwardPage[i], mOldInstr.data(), mOldInstr.size());
			i += mOldInstr.size();

			forwardPage[i++] = 0xe9;		// jmp 
			*(DWORD*)&forwardPage[i] = GetJmpOffset(forwardPage + i - 1, 5, (char*)hookAddr + instrLen);


			// 为目标地址挂hook
			jmpInstr[0] = 0xe9;		// jmp
			*(DWORD*)&jmpInstr[1] = GetJmpOffset(hookAddr, 5, mforwardPage);

			for (int i = 5; i < instrLen; i++) {
				jmpInstr[i] = 0x90;		// nop
			}
		}
		else {

		}

		mProcess->WriteMemory(hookAddr, jmpInstr.data(), instrLen);
		mProcess->SetProtect(hookAddr, instrLen, oldProtect);
	}

	// 卸载Hook
	void Uninstall() {
		auto oldProtect = mProcess->SetProtect(mHookAddr, mOldInstr.size(), PAGE_EXECUTE_READWRITE);
		mProcess->WriteMemory(mOldInstr.data(), mOldInstr.data(), mOldInstr.size());
		mProcess->SetProtect(mHookAddr, mOldInstr.size(), oldProtect);
		VirtualFree(mforwardPage, 0, MEM_RELEASE);
	}


private:
	int64_t GetJmpOffset(void* curAddr, size_t instrLen, void* desAddr) {
		size_t curAddr_ = (size_t)curAddr;;
		size_t desAddr_ = (size_t)desAddr;
		return desAddr_ - curAddr_ - instrLen;
	}

private:
	Process* mProcess;
	void* mHookAddr;
	void* mJmpAddr;
	void* mforwardPage;
	std::vector<char> mOldInstr;
};

} // namespace geek

#endif // GEEK_INLINE_HOOK_H_
