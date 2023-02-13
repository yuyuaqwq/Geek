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

		uint64_t forward_page_base;
		uint64_t ret_addr;
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

		uint32_t forward_page_base;
		uint32_t ret_addr;
		uint32_t esp;
		uint32_t stack[];
	};
	
	typedef void (*HookCallback32)(uint32_t context);
	typedef void (*HookCallback64)(uint64_t context);

public:
	explicit InlineHook(Process* process = nullptr) : m_process{ process }, m_hook_addr{ nullptr }, m_jmp_addr{ nullptr }, m_forward_page{ nullptr }{
		
	}
	~InlineHook() {

	}

public:

	/*
	* 安装转发调用Hook
	* 被hook处用于覆写的指令不能存在相对偏移指令，如0xe8、0xe9
	* x86要求instr_size>=5，x64要求instr_size>=14
	* forward_page是转发页面，至少需要0x1000，前0x1000不可覆写，可以指定较多的空间，便于交互数据
	* 跨进程请关闭/GS(安全检查)，避免生成__security_cookie插入代码
	* 如果需要修改rsp或者ret_addr，注意堆栈平衡，push和pop顺序为  push esp -> push ret_addr -> push xxx  call  pop xxx -> pop&save ret_addr -> pop esp -> 执行原指令 -> get&push ret_addr -> ret  
	* 实现接管：
		* 在函数起始hook
		* exec_old_instr = false
		* callback中指定 ret_addr = stack[0]
		* callback中 context->esp -= 4 / context->rsp -= 8	; 跳过外部call到该函数的返回地址
	*/
	bool Install(PVOID64 hook_addr, size_t instr_size, PVOID64 callback, size_t forward_page_size = 0x1000, bool exec_old_instr = true) {
		Uninstall();
		if (forward_page_size < 0x1000) {
			forward_page_size = 0x1000;
		}

		m_forward_page = m_process->AllocMemory(NULL, forward_page_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!m_forward_page) {
			return false;
		}
		
		// 处理转发页面指令
		std::vector<char> forward_page(forward_page_size);
		auto forward_page_temp = forward_page.data();

		uint64_t forward_page_uint = (uint64_t)m_forward_page;

		// 保存原指令
		m_old_instr.resize(instr_size);
		if (!m_process->ReadMemory(hook_addr, m_old_instr.data(), instr_size)) {
			return false;
		}
		
		std::vector<char> jmp_instr(instr_size);
		bool res;
		if (m_process->IsX86()) {
			if (instr_size < 5) {
				return false;
			}

			int i = 0;

			forward_page_temp[i++] = 0x54;		// push esp

			// push hook_addr + instr_size
			forward_page_temp[i++] = 0x68;
			*(uint32_t*)&forward_page_temp[i] = (uint32_t)hook_addr + instr_size;
			i += 4;

			// push forward_page
			forward_page_temp[i++] = 0x68;
			*(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint;
			i += 4;


			forward_page_temp[i++] = 0x60;		// pushad
			forward_page_temp[i++] = 0x9c;		// pushfd

			// 传递参数
			forward_page_temp[i++] = 0x54;		// push esp

			forward_page_temp[i++] = 0xe8;		// call callback
			*(uint32_t*)&forward_page_temp[i] = GetJmpOffset((PVOID64)(forward_page_uint + i - 1), 5, callback);
			i += 4;

			forward_page_temp[i++] = 0x5c;		// pop esp

			forward_page_temp[i++] = 0x9d;		// popfd
			forward_page_temp[i++] = 0x61;		// popad

			
			forward_page_temp[i++] = 0x83;		// add esp, 4，跳过forwardPage
			forward_page_temp[i++] = 0xc4;
			forward_page_temp[i++] = 0x04;



			// 在原指令执行前还原所有环境，包括压入的ret_addr
			// 要用eax，先存到内存里
			// mov [forwardPage + 0x1000 - 4], eax
			forward_page_temp[i++] = 0xa3;
			*(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint + 0x1000 - 4;
			i += 4;

			// 接下来把retAddr存到内存里
			forward_page_temp[i++] = 0x58;		// pop eax，弹出压入的retAddr
			// mov [forwardPage + 0x1000 - 8], eax
			forward_page_temp[i++] = 0xa3;
			*(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint + 0x1000 - 8;
			i += 4;

			// mov eax, [forwardPage + 0x1000 - 4]，恢复eax
			forward_page_temp[i++] = 0xa1;
			*(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint + 0x1000 - 4;
			i += 4;

			// 在执行前设置esp
			forward_page_temp[i++] = 0x5c;		// pop esp，弹出压入的esp

			if (exec_old_instr) {
				// 执行原指令
				memcpy(&forward_page_temp[i], m_old_instr.data(), m_old_instr.size());
				i += m_old_instr.size();
			}

			// 恢复ret_addr环境
			// mov [forwardPage + 0x1000 - 4], eax，还是先保存eax
			forward_page_temp[i++] = 0xa3;
			*(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint + 0x1000 - 4;
			i += 4;


			// mov eax, [forwardPage + 0x1000 - 8]，保存的ret_addr
			forward_page_temp[i++] = 0xa1;
			*(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint + 0x1000 - 8;
			i += 4;
			// push eax
			forward_page_temp[i++] = 0x50;

			// mov eax, [forwardPage + 0x1000 - 4]，恢复eax
			forward_page_temp[i++] = 0xa1;
			*(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint + 0x1000 - 4;
			i += 4;


			// 转回去继续执行
			//forwardPage[i++] = 0xe9;		// jmp 
			//*(uint32_t*)&forwardPage[i] = GetJmpOffset(forwardPage + i - 1, 5, (char*)hookAddr + instrLen);
			
			forward_page_temp[i++] = 0xc3;		// ret

			// 为目标地址挂hook
			jmp_instr[0] = 0xe9;		// jmp
			*(uint32_t*)&jmp_instr[1] = GetJmpOffset(hook_addr, 5, m_forward_page);

			for (int i = 5; i < instr_size; i++) {
				jmp_instr[i] = 0x90;		// nop
			}
		}
		else {
			if (instr_size < 14) {
				return false;
			}

			int i = 0;

			forward_page_temp[i++] = 0x54;		// push rsp

			// 提前压入转回地址，以便HookCallback能够修改
			forward_page_temp[i++] = 0x68;		// push low_addr
			*(uint32_t*)&forward_page_temp[i] = ((uint64_t)hook_addr + instr_size) & 0xffffffff;
			i += 4;
			forward_page_temp[i++] = 0xc7;		// mov dword ptr ss:[rsp+4], highAddr
			forward_page_temp[i++] = 0x44;
			forward_page_temp[i++] = 0x24;
			forward_page_temp[i++] = 0x04;
			*(uint32_t*)&forward_page_temp[i] = ((uint64_t)hook_addr + instr_size) >> 32;
			i += 4;


			// push forward_page_low
			forward_page_temp[i++] = 0x68;
			*(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint;
			i += 4;
			forward_page_temp[i++] = 0xc7;		// mov dword ptr ss:[rsp+4], forwardPageHigh
			forward_page_temp[i++] = 0x44;
			forward_page_temp[i++] = 0x24;
			forward_page_temp[i++] = 0x04;
			*(uint32_t*)&forward_page_temp[i] = forward_page_uint >> 32;
			i += 4;


			forward_page_temp[i++] = 0x50;		// push rax
			forward_page_temp[i++] = 0x51;		// push rcx
			forward_page_temp[i++] = 0x52;		// push rdx
			forward_page_temp[i++] = 0x53;		// push rbx
			forward_page_temp[i++] = 0x54;		// push rsp
			forward_page_temp[i++] = 0x55;		// push rbp
			forward_page_temp[i++] = 0x56;		// push rsi
			forward_page_temp[i++] = 0x57;		// push rdi
			forward_page_temp[i++] = 0x41;		// push r8
			forward_page_temp[i++] = 0x50;
			forward_page_temp[i++] = 0x41;		// push r9
			forward_page_temp[i++] = 0x51;
			forward_page_temp[i++] = 0x41;		// push r10
			forward_page_temp[i++] = 0x52;
			forward_page_temp[i++] = 0x41;		// push r11
			forward_page_temp[i++] = 0x53;
			forward_page_temp[i++] = 0x41;		// push r12
			forward_page_temp[i++] = 0x54;
			forward_page_temp[i++] = 0x41;		// push r13
			forward_page_temp[i++] = 0x55;
			forward_page_temp[i++] = 0x41;		// push r14
			forward_page_temp[i++] = 0x56;
			forward_page_temp[i++] = 0x41;		// push r15
			forward_page_temp[i++] = 0x57;
			forward_page_temp[i++] = 0x9c;		// pushfq


			// 遵循x64调用约定，为当前函数的使用提前分配栈空间
			forward_page_temp[i++] = 0x48;		// sub rsp, 20
			forward_page_temp[i++] = 0x83;
			forward_page_temp[i++] = 0xec;
			forward_page_temp[i++] = 0x20;

			// 传递参数
			forward_page_temp[i++] = 0x48;		// lea rcx, [rsp+20]
			forward_page_temp[i++] = 0x8d;
			forward_page_temp[i++] = 0x4c;
			forward_page_temp[i++] = 0x24;
			forward_page_temp[i++] = 0x20;



			forward_page_temp[i++] = 0x48;		// mov rax, addr
			forward_page_temp[i++] = 0xb8;
			*(uint64_t*)&forward_page_temp[i] = (uint64_t)callback;
			i += 8;

			forward_page_temp[i++] = 0xff;		// call rax
			forward_page_temp[i++] = 0xd0;

			// 回收栈空间
			forward_page_temp[i++] = 0x48;		// add rsp, 20
			forward_page_temp[i++] = 0x83;
			forward_page_temp[i++] = 0xc4;
			forward_page_temp[i++] = 0x20;


			forward_page_temp[i++] = 0x9d;		// popfq
			forward_page_temp[i++] = 0x41;		// pop r15
			forward_page_temp[i++] = 0x5f;
			forward_page_temp[i++] = 0x41;		// pop r14
			forward_page_temp[i++] = 0x5e;
			forward_page_temp[i++] = 0x41;		// pop r13
			forward_page_temp[i++] = 0x5d;
			forward_page_temp[i++] = 0x41;		// pop r12
			forward_page_temp[i++] = 0x5c;
			forward_page_temp[i++] = 0x41;		// pop r11
			forward_page_temp[i++] = 0x5b;
			forward_page_temp[i++] = 0x41;		// pop r10
			forward_page_temp[i++] = 0x5a;
			forward_page_temp[i++] = 0x41;		// pop r9
			forward_page_temp[i++] = 0x59;
			forward_page_temp[i++] = 0x41;		// pop r8
			forward_page_temp[i++] = 0x58;
			forward_page_temp[i++] = 0x5f;		// pop rdi
			forward_page_temp[i++] = 0x5e;		// pop rsi
			forward_page_temp[i++] = 0x5d;		// pop rbp
			forward_page_temp[i++] = 0x5c;		// pop rsp
			forward_page_temp[i++] = 0x5b;		// pop rbx
			forward_page_temp[i++] = 0x5a;		// pop rdx
			forward_page_temp[i++] = 0x59;		// pop rcx
			forward_page_temp[i++] = 0x58;		// pop rax


			forward_page_temp[i++] = 0x48;		// add esp, 8，跳过forwardPage
			forward_page_temp[i++] = 0x83;
			forward_page_temp[i++] = 0xc4;
			forward_page_temp[i++] = 0x08;



			// 在原指令执行前还原所有环境，包括压入的retAddr
			// 要用rax，先存到内存里
			// mov [forwardPage + 0x1000 - 8], rax
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0xa3;
			*(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0x1000 - 8;
			i += 8;

			// 接下来把retAddr存到内存里
			forward_page_temp[i++] = 0x58;		// pop rax，弹出压入的retAddr
			// mov [forwardPage + 0x1000 - 16], rax
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0xa3;
			*(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0x1000 - 16;
			i += 8;

			// mov rax, [forwardPage + 0x1000 - 8]，恢复rax
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0xa1;
			*(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0x1000 - 8;
			i += 8;

			// 在执行前设置rsp
			forward_page_temp[i++] = 0x5c;		// pop rsp，弹出压入的esp

			if (exec_old_instr) {
				// 执行原指令
				memcpy(&forward_page_temp[i], m_old_instr.data(), m_old_instr.size());
				i += m_old_instr.size();
			}


			// 恢复retAddr环境
			// mov [forwardPage + 0x1000 - 8], rax，还是先保存eax
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0xa3;
			*(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0x1000 - 8;
			i += 8;

			// mov rax, [forwardPage + 0x1000 - 16]，保存的retAddr
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0xa1;
			*(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0x1000 - 16;
			i += 8;
			// push rax
			forward_page_temp[i++] = 0x50;

			// mov rax, [forwardPage + 0x1000 - 8]，恢复eax
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0xa1;
			*(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0x1000 - 8;
			i += 8;

			// 转回去继续执行
			forward_page_temp[i++] = 0xc3;		// ret


			// 为目标地址挂hook
			jmp_instr[0] = 0x68;		// push lowAddr
			*(uint32_t*)&jmp_instr[1] = (uint64_t)forward_page_uint & 0xffffffff;
			jmp_instr[5] = 0xc7;		// mov dword ptr ss:[rsp+4], highAddr
			jmp_instr[6] = 0x44;
			jmp_instr[7] = 0x24;
			jmp_instr[8] = 0x04;
			*(uint32_t*)&jmp_instr[9] = (uint64_t)forward_page_uint >> 32;
			jmp_instr[13] = 0xc3;		// ret

			for (int i = 14; i < instr_size; i++) {
				jmp_instr[i] = 0x90;		// nop
			}
		}
		m_process->WriteMemory(m_forward_page, forward_page_temp, forward_page_size);
		m_process->WriteMemory(hook_addr, &jmp_instr[0], instr_size, true);
		return true;
	}

	/*
	* 卸载Hook
	*/
	void Uninstall() {
		if (m_hook_addr) {
			m_process->WriteMemory(m_hook_addr, m_old_instr.data(), m_old_instr.size(), true);
		}
		if (m_forward_page) {
			m_process->FreeMemory(m_forward_page);
		}
	}

	PVOID64 GetForwardPage() {
		return m_forward_page;
	}

private:
	Process* m_process;
	PVOID64 m_hook_addr;
	PVOID64 m_jmp_addr;
	PVOID64 m_forward_page;
	std::vector<char> m_old_instr;

public:
	static uint64_t GetJmpOffset(PVOID64 instr_addr, size_t instr_size, PVOID64 jmp_addr) {
		uint64_t instr_addr_ = (uint64_t)instr_addr;;
		uint64_t jmp_addr_ = (uint64_t)jmp_addr;
		return jmp_addr_ - instr_addr_ - instr_size;
	}

#define EMITASM_GET_CURRENT_ADDR() 0xe8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x48, 0x8c, 0xc0, 0x05, 		// call next;    next: pop eax/rax;    add eax/rax, 5;

	/* 定位kernel32
	mov eax, dword ptr fs : [30h]   ;指向PEB结构
    mov eax, dword ptr[eax + 0Ch]   ;指向LDR Ptr32 _PEB_LDR_DATA
    mov eax, dword ptr[eax + 0Ch]   ;指向InLoadOrderModuleList _LIST_ENTRY
    mov eax, dword ptr[eax]         ;移动_LIST_ENTRY
    mov eax, dword ptr[eax]         ;指向Kernel32
    mov eax, dword ptr[eax + 18h]   ;指向DllBase基址
    ret
	*/

};

} // namespace geek

#endif // GEEK_HOOK_INLINE_HOOK_H_
