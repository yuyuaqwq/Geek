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
		uint64_t r15;
		uint64_t r14;
		uint64_t r13;
		uint64_t r12;
		uint64_t r11;
		uint64_t r10;
		uint64_t r9;
		uint64_t r8;
		uint64_t rdi;
		uint64_t rsi;
		uint64_t rsp;
		uint64_t rbp;
		uint64_t rbx;
		uint64_t rdx;
		uint64_t rcx;
		uint64_t rax;
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
	// x86要求instrLen>=5，x64要求instrLen>=14
	bool Install(void* hookAddr, size_t instrLen, HookCallBack callback) {
		mforwardPage = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!mforwardPage) {
			return false;
		}
		
		// 保存原指令
		mOldInstr.resize(instrLen);
		memcpy(mOldInstr.data(), hookAddr, instrLen);
		
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

			// 传递参数
			forwardPage[i++] = 0x54;		// push esp

			forwardPage[i++] = 0xe8;		// call
			*(uint32_t*)&forwardPage[i] = GetJmpOffset(forwardPage + i - 1, 5, callback);
			i += 4;

			forwardPage[i++] = 0x5c;		// pop esp

			forwardPage[i++] = 0x9d;		// popfd
			forwardPage[i++] = 0x61;		// popad

			// 执行原指令
			memcpy(&forwardPage[i], mOldInstr.data(), mOldInstr.size());
			i += mOldInstr.size();

			// 转回去继续执行
			forwardPage[i++] = 0xe9;		// jmp 
			*(uint32_t*)&forwardPage[i] = GetJmpOffset(forwardPage + i - 1, 5, (char*)hookAddr + instrLen);


			// 为目标地址挂hook
			jmpInstr[0] = 0xe9;		// jmp
			*(uint32_t*)&jmpInstr[1] = GetJmpOffset(hookAddr, 5, mforwardPage);

			for (int i = 5; i < instrLen; i++) {
				jmpInstr[i] = 0x90;		// nop
			}
		}
		else {
			if (instrLen < 14) {
				return false;
			}

			// 处理转发页面指令
			auto forwardPage = (char*)mforwardPage;
			int i = 0;

			forwardPage[i++] = 0x50;		// push rax
			forwardPage[i++] = 0x51;		// push rcx
			forwardPage[i++] = 0x52;		// push rdx
			forwardPage[i++] = 0x53;		// push rbx
			forwardPage[i++] = 0x54;		// push rsp
			forwardPage[i++] = 0x55;		// push rbp
			forwardPage[i++] = 0x56;		// push rsi
			forwardPage[i++] = 0x57;		// push rdi
			forwardPage[i++] = 0x41;		// push r8
			forwardPage[i++] = 0x50;
			forwardPage[i++] = 0x41;		// push r9
			forwardPage[i++] = 0x51;
			forwardPage[i++] = 0x41;		// push r10
			forwardPage[i++] = 0x52;
			forwardPage[i++] = 0x41;		// push r11
			forwardPage[i++] = 0x53;
			forwardPage[i++] = 0x41;		// push r12
			forwardPage[i++] = 0x54;
			forwardPage[i++] = 0x41;		// push r13
			forwardPage[i++] = 0x55;
			forwardPage[i++] = 0x41;		// push r14
			forwardPage[i++] = 0x56;
			forwardPage[i++] = 0x41;		// push r15
			forwardPage[i++] = 0x57;
			forwardPage[i++] = 0x9c;		// pushfq


			// 为当前函数的使用提前分配栈空间
			forwardPage[i++] = 0x48;		// sub rsp, 20
			forwardPage[i++] = 0x83;
			forwardPage[i++] = 0xec;
			forwardPage[i++] = 0x20;

			// 传递参数
			forwardPage[i++] = 0x48;		// lea rcx, [rsp+20]
			forwardPage[i++] = 0x8d;
			forwardPage[i++] = 0x4c;
			forwardPage[i++] = 0x24;
			forwardPage[i++] = 0x20;



			forwardPage[i++] = 0x48;		// mov rax, addr
			forwardPage[i++] = 0xb8;
			*(uint64_t*)&forwardPage[i] = (uint64_t)callback;
			i += 8;

			forwardPage[i++] = 0xff;		// call rax
			forwardPage[i++] = 0xd0;

			// 回收栈空间
			forwardPage[i++] = 0x48;		// add rsp, 20
			forwardPage[i++] = 0x83;
			forwardPage[i++] = 0xc4;
			forwardPage[i++] = 0x20;


			forwardPage[i++] = 0x9d;		// popfq
			forwardPage[i++] = 0x41;		// pop r15
			forwardPage[i++] = 0x5f;
			forwardPage[i++] = 0x41;		// pop r14
			forwardPage[i++] = 0x5e;
			forwardPage[i++] = 0x41;		// pop r13
			forwardPage[i++] = 0x5d;
			forwardPage[i++] = 0x41;		// pop r12
			forwardPage[i++] = 0x5c;
			forwardPage[i++] = 0x41;		// pop r11
			forwardPage[i++] = 0x5b;
			forwardPage[i++] = 0x41;		// pop r10
			forwardPage[i++] = 0x5a;
			forwardPage[i++] = 0x41;		// pop r9
			forwardPage[i++] = 0x59;
			forwardPage[i++] = 0x41;		// pop r8
			forwardPage[i++] = 0x58;
			forwardPage[i++] = 0x5f;		// pop rdi
			forwardPage[i++] = 0x5e;		// pop rsi
			forwardPage[i++] = 0x5d;		// pop rbp
			forwardPage[i++] = 0x5c;		// pop rsp
			forwardPage[i++] = 0x5b;		// pop rbx
			forwardPage[i++] = 0x5a;		// pop rdx
			forwardPage[i++] = 0x59;		// pop rcx
			forwardPage[i++] = 0x58;		// pop rax

			// 执行原指令
			memcpy(&forwardPage[i], mOldInstr.data(), mOldInstr.size());
			i += mOldInstr.size();

			// 转回去继续执行
			forwardPage[i++] = 0x68;		// push lowAddr
			*(uint32_t*)&forwardPage[i] = ((uint64_t)hookAddr + instrLen) & 0xffffffff;
			i += 4;
			forwardPage[i++] = 0xc7;		// mov dword ptr ss:[rsp+4], highAddr
			forwardPage[i++] = 0x44;
			forwardPage[i++] = 0x24;
			forwardPage[i++] = 0x04;
			*(uint32_t*)&forwardPage[i] = ((uint64_t)hookAddr + instrLen) >> 32;
			i += 4;
			forwardPage[i++] = 0xc3;		// ret


			// 为目标地址挂hook
			jmpInstr[0] = 0x68;		// push lowAddr
			*(uint32_t*)&jmpInstr[1] = (uint64_t)forwardPage & 0xffffffff;
			jmpInstr[5] = 0xc7;		// mov dword ptr ss:[rsp+4], highAddr
			jmpInstr[6] = 0x44;
			jmpInstr[7] = 0x24;
			jmpInstr[8] = 0x04;
			*(uint32_t*)&jmpInstr[9] = (uint64_t)forwardPage >> 32;
			jmpInstr[13] = 0xc3;		// ret

			for (int i = 14; i < instrLen; i++) {
				jmpInstr[i] = 0x90;		// nop
			}
		}
		auto oldProtect = mProcess->SetProtect(hookAddr, instrLen, PAGE_EXECUTE_READWRITE);
		mProcess->WriteMemory((char*)hookAddr, &jmpInstr[0], instrLen);
		mProcess->SetProtect((char*)hookAddr, instrLen, oldProtect);
	}

	// 卸载Hook
	void Uninstall() {
		auto oldProtect = mProcess->SetProtect(mHookAddr, mOldInstr.size(), PAGE_EXECUTE_READWRITE);
		mProcess->WriteMemory(mOldInstr.data(), mOldInstr.data(), mOldInstr.size());
		mProcess->SetProtect(mHookAddr, mOldInstr.size(), oldProtect);
		VirtualFree(mforwardPage, 0, MEM_RELEASE);
	}

private:
	size_t GetJmpOffset(void* curAddr, size_t instrLen, void* desAddr) {
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
