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

		uint64_t forwardPage;
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

		uint32_t forwardPage;
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
	* ��װת������Hook
	* ��hook�����ڸ�д��ָ��ܴ������ƫ��ָ���0xe8��0xe9
	* x86Ҫ��instrLen>=5��x64Ҫ��instrLen>=14
	* forwardPage��ת��ҳ�棬������Ҫ0x1000��ǰ0x1000���ɸ�д������ָ���϶�Ŀռ䣬���ڽ�������
	* �������ر�/GS(��ȫ���)����������__security_cookie�������
	* �����Ҫ�޸�rsp����retAddr��ע���ջƽ�⣬push��pop˳��Ϊ  push esp -> push retAddr -> push xxx  call  pop xxx -> pop&save retAddr -> pop esp -> ִ��ԭָ�� -> get&push retAddr -> ret  
	*/
	bool Install(PVOID64 hookAddr, size_t instrLen, PVOID64 callback, size_t forwardPageSize = 0x1000,bool execOldInstr = true) {
		Uninstall();
		if (forwardPageSize == 0) {
			forwardPageSize = 0x1000;
		}

		mforwardPage = mProcess->AllocMemory(NULL, forwardPageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!mforwardPage) {
			return false;
		}
		
		// ����ת��ҳ��ָ��
		std::vector<char> forwardPage(forwardPageSize);
		auto forwardPageTemp = forwardPage.data();

		uint64_t forwardPageUint = (uint64_t)mforwardPage;

		// ����ԭָ��
		mOldInstr.resize(instrLen);
		if (!mProcess->ReadMemory(hookAddr, mOldInstr.data(), instrLen)) {
			return false;
		}
		
		std::vector<char> jmpInstr(instrLen);
		bool res;
		if (mProcess->IsX86()) {
			if (instrLen < 5) {
				return false;
			}

			int i = 0;

			forwardPageTemp[i++] = 0x54;		// push esp

			// push hookAddr+instrLen
			forwardPageTemp[i++] = 0x68;
			*(uint32_t*)&forwardPageTemp[i] = (uint32_t)hookAddr + instrLen;
			i += 4;

			// push forwardPage
			forwardPageTemp[i++] = 0x68;
			*(uint32_t*)&forwardPageTemp[i] = (uint32_t)forwardPageUint;
			i += 4;


			forwardPageTemp[i++] = 0x60;		// pushad
			forwardPageTemp[i++] = 0x9c;		// pushfd

			// ���ݲ���
			forwardPageTemp[i++] = 0x54;		// push esp

			forwardPageTemp[i++] = 0xe8;		// call callback
			*(uint32_t*)&forwardPageTemp[i] = GetJmpOffset((PVOID64)(forwardPageUint + i - 1), 5, callback);
			i += 4;

			forwardPageTemp[i++] = 0x5c;		// pop esp

			forwardPageTemp[i++] = 0x9d;		// popfd
			forwardPageTemp[i++] = 0x61;		// popad

			
			forwardPageTemp[i++] = 0x83;		// add esp, 4������forwardPage
			forwardPageTemp[i++] = 0xc4;
			forwardPageTemp[i++] = 0x04;



			// ��ԭָ��ִ��ǰ��ԭ���л���������ѹ���retAddr
			// Ҫ��eax���ȴ浽�ڴ���
			// mov [forwardPage + 0x1000 - 4], eax
			forwardPageTemp[i++] = 0xa3;
			*(uint32_t*)&forwardPageTemp[i] = (uint32_t)forwardPageUint + 0x1000 - 4;
			i += 4;

			// ��������retAddr�浽�ڴ���
			forwardPageTemp[i++] = 0x58;		// pop eax������ѹ���retAddr
			// mov [forwardPage + 0x1000 - 8], eax
			forwardPageTemp[i++] = 0xa3;
			*(uint32_t*)&forwardPageTemp[i] = (uint32_t)forwardPageUint + 0x1000 - 8;
			i += 4;

			// mov eax, [forwardPage + 0x1000 - 4]���ָ�eax
			forwardPageTemp[i++] = 0xa1;
			*(uint32_t*)&forwardPageTemp[i] = (uint32_t)forwardPageUint + 0x1000 - 4;
			i += 4;

			// ��ִ��ǰ����esp
			forwardPageTemp[i++] = 0x5c;		// pop esp������ѹ���esp

			if (execOldInstr) {
				// ִ��ԭָ��
				memcpy(&forwardPageTemp[i], mOldInstr.data(), mOldInstr.size());
				i += mOldInstr.size();
			}

			// �ָ�retAddr����
			// mov [forwardPage + 0x1000 - 4], eax�������ȱ���eax
			forwardPageTemp[i++] = 0xa3;
			*(uint32_t*)&forwardPageTemp[i] = (uint32_t)forwardPageUint + 0x1000 - 4;
			i += 4;


			// mov eax, [forwardPage + 0x1000 - 8]�������retAddr
			forwardPageTemp[i++] = 0xa1;
			*(uint32_t*)&forwardPageTemp[i] = (uint32_t)forwardPageUint + 0x1000 - 8;
			i += 4;
			// push eax
			forwardPageTemp[i++] = 0x50;

			// mov eax, [forwardPage + 0x1000 - 4]���ָ�eax
			forwardPageTemp[i++] = 0xa1;
			*(uint32_t*)&forwardPageTemp[i] = (uint32_t)forwardPageUint + 0x1000 - 4;
			i += 4;


			// ת��ȥ����ִ��
			//forwardPage[i++] = 0xe9;		// jmp 
			//*(uint32_t*)&forwardPage[i] = GetJmpOffset(forwardPage + i - 1, 5, (char*)hookAddr + instrLen);
			
			forwardPageTemp[i++] = 0xc3;		// ret

			// ΪĿ���ַ��hook
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

			forwardPageTemp[i++] = 0x54;		// push rsp

			// ��ǰѹ��ת�ص�ַ���Ա�HookCallback�ܹ��޸�
			forwardPageTemp[i++] = 0x68;		// push lowAddr
			*(uint32_t*)&forwardPageTemp[i] = ((uint64_t)hookAddr + instrLen) & 0xffffffff;
			i += 4;
			forwardPageTemp[i++] = 0xc7;		// mov dword ptr ss:[rsp+4], highAddr
			forwardPageTemp[i++] = 0x44;
			forwardPageTemp[i++] = 0x24;
			forwardPageTemp[i++] = 0x04;
			*(uint32_t*)&forwardPageTemp[i] = ((uint64_t)hookAddr + instrLen) >> 32;
			i += 4;


			// push forwardPageLow
			forwardPageTemp[i++] = 0x68;
			*(uint32_t*)&forwardPageTemp[i] = (uint32_t)forwardPageUint;
			i += 4;
			forwardPageTemp[i++] = 0xc7;		// mov dword ptr ss:[rsp+4], forwardPageHigh
			forwardPageTemp[i++] = 0x44;
			forwardPageTemp[i++] = 0x24;
			forwardPageTemp[i++] = 0x04;
			*(uint32_t*)&forwardPageTemp[i] = forwardPageUint >> 32;
			i += 4;


			forwardPageTemp[i++] = 0x50;		// push rax
			forwardPageTemp[i++] = 0x51;		// push rcx
			forwardPageTemp[i++] = 0x52;		// push rdx
			forwardPageTemp[i++] = 0x53;		// push rbx
			forwardPageTemp[i++] = 0x54;		// push rsp
			forwardPageTemp[i++] = 0x55;		// push rbp
			forwardPageTemp[i++] = 0x56;		// push rsi
			forwardPageTemp[i++] = 0x57;		// push rdi
			forwardPageTemp[i++] = 0x41;		// push r8
			forwardPageTemp[i++] = 0x50;
			forwardPageTemp[i++] = 0x41;		// push r9
			forwardPageTemp[i++] = 0x51;
			forwardPageTemp[i++] = 0x41;		// push r10
			forwardPageTemp[i++] = 0x52;
			forwardPageTemp[i++] = 0x41;		// push r11
			forwardPageTemp[i++] = 0x53;
			forwardPageTemp[i++] = 0x41;		// push r12
			forwardPageTemp[i++] = 0x54;
			forwardPageTemp[i++] = 0x41;		// push r13
			forwardPageTemp[i++] = 0x55;
			forwardPageTemp[i++] = 0x41;		// push r14
			forwardPageTemp[i++] = 0x56;
			forwardPageTemp[i++] = 0x41;		// push r15
			forwardPageTemp[i++] = 0x57;
			forwardPageTemp[i++] = 0x9c;		// pushfq


			// ��ѭx64����Լ����Ϊ��ǰ������ʹ����ǰ����ջ�ռ�
			forwardPageTemp[i++] = 0x48;		// sub rsp, 20
			forwardPageTemp[i++] = 0x83;
			forwardPageTemp[i++] = 0xec;
			forwardPageTemp[i++] = 0x20;

			// ���ݲ���
			forwardPageTemp[i++] = 0x48;		// lea rcx, [rsp+20]
			forwardPageTemp[i++] = 0x8d;
			forwardPageTemp[i++] = 0x4c;
			forwardPageTemp[i++] = 0x24;
			forwardPageTemp[i++] = 0x20;



			forwardPageTemp[i++] = 0x48;		// mov rax, addr
			forwardPageTemp[i++] = 0xb8;
			*(uint64_t*)&forwardPageTemp[i] = (uint64_t)callback;
			i += 8;

			forwardPageTemp[i++] = 0xff;		// call rax
			forwardPageTemp[i++] = 0xd0;

			// ����ջ�ռ�
			forwardPageTemp[i++] = 0x48;		// add rsp, 20
			forwardPageTemp[i++] = 0x83;
			forwardPageTemp[i++] = 0xc4;
			forwardPageTemp[i++] = 0x20;


			forwardPageTemp[i++] = 0x9d;		// popfq
			forwardPageTemp[i++] = 0x41;		// pop r15
			forwardPageTemp[i++] = 0x5f;
			forwardPageTemp[i++] = 0x41;		// pop r14
			forwardPageTemp[i++] = 0x5e;
			forwardPageTemp[i++] = 0x41;		// pop r13
			forwardPageTemp[i++] = 0x5d;
			forwardPageTemp[i++] = 0x41;		// pop r12
			forwardPageTemp[i++] = 0x5c;
			forwardPageTemp[i++] = 0x41;		// pop r11
			forwardPageTemp[i++] = 0x5b;
			forwardPageTemp[i++] = 0x41;		// pop r10
			forwardPageTemp[i++] = 0x5a;
			forwardPageTemp[i++] = 0x41;		// pop r9
			forwardPageTemp[i++] = 0x59;
			forwardPageTemp[i++] = 0x41;		// pop r8
			forwardPageTemp[i++] = 0x58;
			forwardPageTemp[i++] = 0x5f;		// pop rdi
			forwardPageTemp[i++] = 0x5e;		// pop rsi
			forwardPageTemp[i++] = 0x5d;		// pop rbp
			forwardPageTemp[i++] = 0x5c;		// pop rsp
			forwardPageTemp[i++] = 0x5b;		// pop rbx
			forwardPageTemp[i++] = 0x5a;		// pop rdx
			forwardPageTemp[i++] = 0x59;		// pop rcx
			forwardPageTemp[i++] = 0x58;		// pop rax


			forwardPageTemp[i++] = 0x48;		// add esp, 8������forwardPage
			forwardPageTemp[i++] = 0x83;
			forwardPageTemp[i++] = 0xc4;
			forwardPageTemp[i++] = 0x08;



			// ��ԭָ��ִ��ǰ��ԭ���л���������ѹ���retAddr
			// Ҫ��rax���ȴ浽�ڴ���
			// mov [forwardPage + 0x1000 - 8], rax
			forwardPageTemp[i++] = 0x48;
			forwardPageTemp[i++] = 0xa3;
			*(uint64_t*)&forwardPageTemp[i] = (uint64_t)forwardPageUint + 0x1000 - 8;
			i += 8;

			// ��������retAddr�浽�ڴ���
			forwardPageTemp[i++] = 0x58;		// pop rax������ѹ���retAddr
			// mov [forwardPage + 0x1000 - 16], rax
			forwardPageTemp[i++] = 0x48;
			forwardPageTemp[i++] = 0xa3;
			*(uint64_t*)&forwardPageTemp[i] = (uint64_t)forwardPageUint + 0x1000 - 16;
			i += 8;

			// mov rax, [forwardPage + 0x1000 - 8]���ָ�rax
			forwardPageTemp[i++] = 0x48;
			forwardPageTemp[i++] = 0xa1;
			*(uint64_t*)&forwardPageTemp[i] = (uint64_t)forwardPageUint + 0x1000 - 8;
			i += 8;

			// ��ִ��ǰ����rsp
			forwardPageTemp[i++] = 0x5c;		// pop rsp������ѹ���esp

			if (execOldInstr) {
				// ִ��ԭָ��
				memcpy(&forwardPageTemp[i], mOldInstr.data(), mOldInstr.size());
				i += mOldInstr.size();
			}


			// �ָ�retAddr����
			// mov [forwardPage + 0x1000 - 8], rax�������ȱ���eax
			forwardPageTemp[i++] = 0x48;
			forwardPageTemp[i++] = 0xa3;
			*(uint64_t*)&forwardPageTemp[i] = (uint64_t)forwardPageUint + 0x1000 - 8;
			i += 8;

			// mov rax, [forwardPage + 0x1000 - 16]�������retAddr
			forwardPageTemp[i++] = 0x48;
			forwardPageTemp[i++] = 0xa1;
			*(uint64_t*)&forwardPageTemp[i] = (uint64_t)forwardPageUint + 0x1000 - 16;
			i += 8;
			// push rax
			forwardPageTemp[i++] = 0x50;

			// mov rax, [forwardPage + 0x1000 - 8]���ָ�eax
			forwardPageTemp[i++] = 0x48;
			forwardPageTemp[i++] = 0xa1;
			*(uint64_t*)&forwardPageTemp[i] = (uint64_t)forwardPageUint + 0x1000 - 8;
			i += 8;

			// ת��ȥ����ִ��
			forwardPageTemp[i++] = 0xc3;		// ret


			// ΪĿ���ַ��hook
			jmpInstr[0] = 0x68;		// push lowAddr
			*(uint32_t*)&jmpInstr[1] = (uint64_t)forwardPageUint & 0xffffffff;
			jmpInstr[5] = 0xc7;		// mov dword ptr ss:[rsp+4], highAddr
			jmpInstr[6] = 0x44;
			jmpInstr[7] = 0x24;
			jmpInstr[8] = 0x04;
			*(uint32_t*)&jmpInstr[9] = (uint64_t)forwardPageUint >> 32;
			jmpInstr[13] = 0xc3;		// ret

			for (int i = 14; i < instrLen; i++) {
				jmpInstr[i] = 0x90;		// nop
			}
		}
		mProcess->WriteMemory(mforwardPage, forwardPageTemp, forwardPageSize);
		mProcess->WriteMemory(hookAddr, &jmpInstr[0], instrLen, true);
		return true;
	}

	/*
	* ж��Hook
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

#define EMITASM_GET_CURRENT_ADDR() 0xe8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x48, 0x8c, 0xc0, 0x05, 		// call next;    next: pop eax/rax;    add eax/rax, 5;
};

} // namespace geek

#endif // GEEK_HOOK_INLINE_HOOK_H_
