#ifndef GEEK_HOOK_INLINE_HOOK_H_
#define GEEK_HOOK_INLINE_HOOK_H_

#include <type_traits>
#include <vector>

#include <Windows.h>

#include <Geek/Process/process.hpp>


namespace geek {

class InlineHook {
public:

	struct HookContext64 {
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
		uint64_t rsp_invalid;
		uint64_t rbp;
		uint64_t rbx;
		uint64_t rdx;
		uint64_t rcx;
		uint64_t rax;

		uint64_t retAddr;
		uint64_t rsp;
		uint64_t stack[];
	};
	struct HookContext32 {
		uint32_t eflags;
		uint32_t edi;
		uint32_t esi;
		uint32_t ebp;
		uint32_t esp_invalid;
		uint32_t ebx;
		uint32_t edx;
		uint32_t ecx;
		uint32_t eax;

		uint32_t retAddr;
		uint32_t esp;
		uint32_t stack[];
	};
	
	typedef void (*HookCallback32)(uint32_t context);
	typedef void (*HookCallback64)(uint64_t context);

public:
	explicit InlineHook(Process* tProcess = nullptr) : mProcess{ tProcess }, mHookAddr{ nullptr }, mJmpAddr{ nullptr }, mforwardPage{ nullptr }{
		
	}
	~InlineHook() {

	}

public:

	/*
	* 安装转发调用Hook
	* 被hook处用于覆写的指令不能存在相对偏移指令，如0xe8、0xe9
	* x86要求instrLen>=5，x64要求instrLen>=14
	* 自行注意堆栈平衡，push和pop顺序为  push esp -> push retAddr -> push xxx  call  pop xxx -> pop&save retAddr -> pop esp -> 执行原指令 -> get&push retAddr -> ret  
	*/
	bool Install(PVOID64 hookAddr, size_t instrLen, PVOID64 callback, bool execOldInstr = true) {
		Uninstall();
		
		mforwardPage = mProcess->AllocMemory(NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!mforwardPage) {
			return false;
		}
		
		// 处理转发页面指令
		auto forwardPageVector = mProcess->ReadMemory(mforwardPage, 0x1000);
		auto forwardPage = forwardPageVector.data();

		// 保存原指令
		mOldInstr.resize(instrLen);
		memcpy(mOldInstr.data(), hookAddr, instrLen);
		
		std::vector<char> jmpInstr(instrLen);
		bool res;
		if (mProcess->IsX86()) {
			if (instrLen < 5) {
				return false;
			}

			
			int i = 0;

			forwardPage[i++] = 0x54;		// push esp

			// push hookAddr+instrLen
			forwardPage[i++] = 0x68;
			*(uint32_t*)&forwardPage[i] = (uint32_t)hookAddr + instrLen;
			i += 4;



			forwardPage[i++] = 0x60;		// pushad
			forwardPage[i++] = 0x9c;		// pushfd

			// 传递参数
			forwardPage[i++] = 0x54;		// push esp

			forwardPage[i++] = 0xe8;		// call callback
			*(uint32_t*)&forwardPage[i] = GetJmpOffset(forwardPage + i - 1, 5, callback);
			i += 4;

			forwardPage[i++] = 0x5c;		// pop esp

			forwardPage[i++] = 0x9d;		// popfd
			forwardPage[i++] = 0x61;		// popad


			// 在原指令执行前还原所有环境，包括压入的retAddr，以及设置在callback中修改的esp
			// 要用eax，先存到内存里
			// mov [forwardPage + 0x1000 - 4], eax
			forwardPage[i++] = 0xa3;
			*(uint32_t*)&forwardPage[i] = (uint32_t)forwardPage + 0x1000 - 4;
			i += 4;

			// 接下来把retAddr存到内存里
			forwardPage[i++] = 0x58;		// pop eax，弹出压入的retAddr
			// mov [forwardPage + 0x1000 - 8], eax
			forwardPage[i++] = 0xa3;
			*(uint32_t*)&forwardPage[i] = (uint32_t)forwardPage + 0x1000 - 8;
			i += 4;

			// mov eax, [forwardPage + 0x1000 - 4]，恢复eax
			forwardPage[i++] = 0xa1;
			*(uint32_t*)&forwardPage[i] = (uint32_t)forwardPage + 0x1000 - 4;
			i += 4;

			// 在执行前设置esp
			forwardPage[i++] = 0x5c;		// pop esp，弹出压入的esp

			if (execOldInstr) {
				// 执行原指令
				memcpy(&forwardPage[i], mOldInstr.data(), mOldInstr.size());
				i += mOldInstr.size();
			}

			// 恢复retAddr环境
			// mov [forwardPage + 0x1000 - 4], eax，还是先保存eax
			forwardPage[i++] = 0xa3;
			*(uint32_t*)&forwardPage[i] = (uint32_t)forwardPage + 0x1000 - 4;
			i += 4;


			// mov eax, [forwardPage + 0x1000 - 8]，保存的retAddr
			forwardPage[i++] = 0xa1;
			*(uint32_t*)&forwardPage[i] = (uint32_t)forwardPage + 0x1000 - 8;
			i += 4;
			// push eax
			forwardPage[i++] = 0x50;

			// mov eax, [forwardPage + 0x1000 - 4]，恢复eax
			forwardPage[i++] = 0xa1;
			*(uint32_t*)&forwardPage[i] = (uint32_t)forwardPage + 0x1000 - 4;
			i += 4;


			// 转回去继续执行
			//forwardPage[i++] = 0xe9;		// jmp 
			//*(uint32_t*)&forwardPage[i] = GetJmpOffset(forwardPage + i - 1, 5, (char*)hookAddr + instrLen);
			
			forwardPage[i++] = 0xc3;		// ret

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

			int i = 0;

			forwardPage[i++] = 0x54;		// push rsp

			// 提前压入转回地址，以便HookCallback能够修改
			forwardPage[i++] = 0x68;		// push lowAddr
			*(uint32_t*)&forwardPage[i] = ((uint64_t)hookAddr + instrLen) & 0xffffffff;
			i += 4;
			forwardPage[i++] = 0xc7;		// mov dword ptr ss:[rsp+4], highAddr
			forwardPage[i++] = 0x44;
			forwardPage[i++] = 0x24;
			forwardPage[i++] = 0x04;
			*(uint32_t*)&forwardPage[i] = ((uint64_t)hookAddr + instrLen) >> 32;
			i += 4;



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


			// 遵循x64调用约定，为当前函数的使用提前分配栈空间
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


			// 在原指令执行前还原所有环境，包括压入的retAddr，以及设置在callback中修改的rsp
			// 要用rax，先存到内存里
			// mov [forwardPage + 0x1000 - 4], rax
			forwardPage[i++] = 0xa3;
			*(uint64_t*)&forwardPage[i] = (uint64_t)forwardPage + 0x1000 - 4;
			i += 8;

			// 接下来把retAddr存到内存里
			forwardPage[i++] = 0x58;		// pop eax，弹出压入的retAddr
			// mov [forwardPage + 0x1000 - 8], eax
			forwardPage[i++] = 0xa3;
			*(uint32_t*)&forwardPage[i] = (uint32_t)forwardPage + 0x1000 - 8;
			i += 4;

			// mov eax, [forwardPage + 0x1000 - 4]，恢复eax
			forwardPage[i++] = 0xa1;
			*(uint32_t*)&forwardPage[i] = (uint32_t)forwardPage + 0x1000 - 4;
			i += 4;

			// 在执行前设置esp
			forwardPage[i++] = 0x5c;		// pop esp，弹出压入的esp



			if (execOldInstr) {
				// 执行原指令
				memcpy(&forwardPage[i], mOldInstr.data(), mOldInstr.size());
				i += mOldInstr.size();
			}

			// 转回去继续执行
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
		mProcess->WriteMemory(mforwardPage, forwardPage, 0x1000);
		mProcess->WriteMemory(hookAddr, &jmpInstr[0], instrLen, true);
		return true;
	}

	/*
	* 卸载Hook
	*/
	void Uninstall() {
		if (mforwardPage) {
			mProcess->FreeMemory(mforwardPage);
		}
		if (mHookAddr) {
			mProcess->WriteMemory(mHookAddr, mOldInstr.data(), mOldInstr.size(), true);
		}
		
	}

private:
	Process* mProcess;
	PVOID64 mHookAddr;
	PVOID64 mJmpAddr;
	PVOID64 mforwardPage;
	std::vector<char> mOldInstr;

public:
	static uint64_t GetJmpOffset(PVOID64 instrAddr, size_t instrLen, PVOID64 jmpAddr) {
		uint64_t instrAddr_ = (uint64_t)instrAddr;;
		uint64_t jmpAddr_ = (uint64_t)jmpAddr;
		return jmpAddr_ - instrAddr_ - instrLen;
	}

};

} // namespace geek

#endif // GEEK_HOOK_INLINE_HOOK_H_
