#ifndef GEEK_HOOK_INLINE_HOOK_H_
#define GEEK_HOOK_INLINE_HOOK_H_

#include <type_traits>
#include <vector>

#include <Windows.h>

#include <geek/process/process.hpp>


namespace Geek {

class InlineHook {
public:

    enum class Architecture {
        kCurrentRunning,
        kX86,
        kAmd64,
    };

    struct HookContextX86 {
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
    struct HookContextAmd64 {
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

    // 位于Forwa 0xc00 ~ 0xcff 处的结构体
    struct HookContextForwardInfoX86 {
        uint32_t thread_id_lock;
    };

    struct HookContextForwardInfoAmd64 {
        uint64_t thread_id_lock;
    };
    
    typedef bool (*HookCallbackX86)(HookContextX86* context, HookContextForwardInfoX86* forward_info);
    typedef bool (*HookCallbackAmd64)(HookContextAmd64* context, HookContextForwardInfoAmd64* forward_info);

public:
    explicit InlineHook(Process* process = nullptr) : m_process{ process }, m_hook_addr{ 0 }, m_forward_page{ 0 }{ }
    ~InlineHook() {

    }

public:

    /*
    * 安装通用转发调用Hook
        * 可以在任意位置hook，参数为HookContext*，具体类型因处理器架构而异
    * 
    * 被hook处用于覆写的指令不能存在相对偏移指令
        * 如0xe8、0xe9(可解决思路：在转发页面将hook处指令还原，但修改hook处的后继指令为再度跳转，在再度跳转中还原hook并还原后继指令，再跳回后继指令处执行，即可复用hook)
    * 
    * x86要求instr_size>=5，x64要求instr_size>=14，且instr_size不能大于255
    * 
    * forward_page是转发页面，至少需要0x1000，前0x1000不可覆写
        * 可以指定较多的空间，便于交互数据，callback若是forward_offset，也从0x1000计起
    * 
    * 跨进程请关闭/GS(安全检查)，避免生成__security_cookie插入代码
    * 
    * 如果需要修改rsp或者ret_addr，注意堆栈平衡
        * 默认情况下ret_addr是指向被hook处的下一行指令
        * push和pop顺序为    push esp -> push ret_addr -> push xxx    call    pop xxx -> pop&save ret_addr -> pop esp -> 是否执行原指令 -> get&push ret_addr -> ret
    * 
    * 实现接管：
        * 在函数起始hook
        * callback中 context->esp += 4 / context->rsp += 8;	// 跳过外部call到该函数的返回地址
        * callback中指定 ret_addr = stack[0];      // 直接返回到调用被hook函数的调用处
        * callback中返回false      // 不执行原指令
        *
    * 实现监视：
        * 与接管基本一致
        * 需要获取原函数执行结果
            * 直接在callback中再次调用原函数以获取其运行结果
            * 返回false        // 不执行原指令
        * 不需要获取原函数执行结果
            * 不修改esp/rsp以及ret_addr
            * 返回true
    * 
    * Amd64下需要注意Hook时的栈应该以16字节对齐，否则部分指令可能会异常
    */

    bool Install(uint64_t hook_addr, size_t instr_size, uint64_t callback, Architecture arch = Architecture::kCurrentRunning, 
        uint64_t forward_page_size = 0x1000
    ) {
        Uninstall();
        if (forward_page_size < 0x1000) {
            forward_page_size = 0x1000;
        }

        m_forward_page = m_process->AllocMemory(NULL, forward_page_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!m_forward_page) {
            return false;
        }

        // 处理转发页面指令
        std::vector<char> forward_page(forward_page_size, 0);
        auto forward_page_temp = forward_page.data();

        uint64_t forward_page_uint = (uint64_t)m_forward_page;

        // 保存原指令
        m_old_instr.resize(instr_size);
        if (!m_process->ReadMemory(hook_addr, m_old_instr.data(), instr_size)) {
            return false;
        }
        
        std::vector<char> jmp_instr(instr_size);
        if (arch == Architecture::kCurrentRunning) arch = GetCurrentRunningArch();

        switch (arch) {
        case Architecture::kX86: {
            if (instr_size < 5) {
                return false;
            }

            int i = 0;
            
            // 首先获取线程id锁保证线程安全且简单支持嵌套重入
            forward_page_temp[i++] = 0x50;        // push eax
            forward_page_temp[i++] = 0x51;        // push ecx
            forward_page_temp[i++] = 0x9c;        // pushfd


            // GetCurrentThreadId
            // mov eax, dword ptr fs:[00000024h]
            forward_page_temp[i++] = 0x64;
            forward_page_temp[i++] = 0xa1;
            forward_page_temp[i++] = 0x24;
            forward_page_temp[i++] = 0x00;
            forward_page_temp[i++] = 0x00;
            forward_page_temp[i++] = 0x00;

            // 直接检查是否嵌套重入，是则是从callback再次回调到当前函数的，直接执行原函数流程
            // cmp eax, [forward_page + 0xc00 + 0]
            forward_page_temp[i++] = 0x3b;
            forward_page_temp[i++] = 0x05;
            *(uint32_t*)&forward_page[i] = (uint32_t)forward_page_uint + 0xc00 + 0;
            i += 4;

            // jne _retry
            forward_page_temp[i++] = 0x75;
            forward_page_temp[i++] = 3 + m_old_instr.size() + 5;      // 跳过原指令执行

            forward_page_temp[i++] = 0x9d;        // popfd
            forward_page_temp[i++] = 0x59;        // pop ecx
            forward_page_temp[i++] = 0x58;        // pop eax

            memcpy(&forward_page_temp[i], m_old_instr.data(), m_old_instr.size());
            i += m_old_instr.size();

            // 跳回原函数正常执行
            i += MakeJmp(arch, &forward_page_temp[i], 0, forward_page_uint + i, hook_addr + instr_size);


            // 抢占锁，ecx保持为当前线程id
            // mov ecx, eax
            forward_page_temp[i++] = 0x89;
            forward_page_temp[i++] = 0xc1;
        // _retry:
            // xor eax, eax
            forward_page_temp[i++] = 0x31;
            forward_page_temp[i++] = 0xc0;
            

            // lock cmpxchg dword ptr ds:[forward_page + 0xc00 + 0], ecx
            forward_page_temp[i++] = 0xf0;
            forward_page_temp[i++] = 0x0f;
            forward_page_temp[i++] = 0xb1;
            forward_page_temp[i++] = 0x0d;
            *(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint + 0xc00;
            i += 4;

            // 上锁成功，直接继续
            // je _end
            forward_page_temp[i++] = 0x74;
            forward_page_temp[i++] = 0x02;      // +2

            // jmp _retry
            forward_page_temp[i++] = 0xeb;
            forward_page_temp[i++] = 0xf2;      // -14

        // _end:
            forward_page_temp[i++] = 0x9d;        // popfd
            forward_page_temp[i++] = 0x59;        // pop ecx
            forward_page_temp[i++] = 0x58;        // pop eax



            // 准备调用回调函数

            forward_page_temp[i++] = 0x54;        // push esp

            // push ret_addr        ; hook_addr + instr_size
            forward_page_temp[i++] = 0x68;
            *(uint32_t*)&forward_page_temp[i] = (uint32_t)hook_addr + instr_size;
            i += 4;

            // push forward_page
            forward_page_temp[i++] = 0x68;
            *(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint;
            i += 4;


            forward_page_temp[i++] = 0x60;        // pushad
            forward_page_temp[i++] = 0x9c;        // pushfd

            // 传递参数
            forward_page_temp[i++] = 0x54;        // push esp       ; context

            forward_page_temp[i++] = 0xe8;        // call callback
            *(uint32_t*)&forward_page_temp[i] = GetJmpOffset((forward_page_uint + i - 1), 5, callback);
            i += 4;

            // 先把callback返回值保存起来
            // mov [forward_page + 0xd00 + 0], al
            forward_page_temp[i++] = 0xa2;
            *(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint + 0xd00 + 0;
            i += 4;


            forward_page_temp[i++] = 0x5c;        // pop esp

            forward_page_temp[i++] = 0x9d;        // popfd
            forward_page_temp[i++] = 0x61;        // popad


            forward_page_temp[i++] = 0x83;        // add esp        ;跳过forward_page
            forward_page_temp[i++] = 0xc4;
            forward_page_temp[i++] = 0x04;




            // 在原指令执行前还原所有环境，包括压入的ret_addr
            // 要用eax，先存到内存里
            // mov [forward_page + 0xd00 + 4], eax
            forward_page_temp[i++] = 0xa3;
            *(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint + 0xd00 + 4;
            i += 4;

            // 接下来把ret_addr临时存到内存里
            forward_page_temp[i++] = 0x58;        // pop eax        ;弹出压入的ret_addr
            // mov [forward_page + 0xd00 + 8], eax
            forward_page_temp[i++] = 0xa3;
            *(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint + 0xd00 + 8;
            i += 4;

            // 在执行前恢复esp
            forward_page_temp[i++] = 0x5c;        // pop esp        ;弹出压入的esp


            // 拿到callback的返回值
            // mov al, [forward_page + 0xd00 + 0]
            forward_page_temp[i++] = 0xa0;
            *(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint + 0xd00 + 0;
            i += 4;

            
            forward_page_temp[i++] = 0x9c;      // pushfd
            // cmp al, 0
            forward_page_temp[i++] = 0x3c;
            forward_page_temp[i++] = 0x00;

            // mov eax, [forward_page + 0xd00 + 4]      ;恢复eax
            forward_page_temp[i++] = 0xa1;
            *(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint + 0xd00 + 4;
            i += 4;

            // je _skip_exec_old_insrt
            forward_page_temp[i++] = 0x74;
            forward_page_temp[i++] = 1 + m_old_instr.size() + 2;

            forward_page_temp[i++] = 0x9d;      // popfd
            // 执行原指令
            memcpy(&forward_page_temp[i], m_old_instr.data(), m_old_instr.size());
            i += m_old_instr.size();
            // jmp _next_exec_old_insrt
            forward_page_temp[i++] = 0xeb;
            forward_page_temp[i++] = 0x01;      // +1

        // _skip_exec_old_insrt:
            forward_page_temp[i++] = 0x9d;      // popfd
        // _next_exec_old_insrt:
            
            // 恢复ret_addr环境
            // mov [forward_page + 0xd00 + 4], eax      ;还是先保存eax
            forward_page_temp[i++] = 0xa3;
            *(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint + 0xd00 + 4;
            i += 4;

            // mov eax, [forward_page + 0xd00 + 8]      ;保存的ret_addr
            forward_page_temp[i++] = 0xa1;
            *(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint + 0xd00 + 8;
            i += 4;
            // push eax     ; 推入ret_addr
            forward_page_temp[i++] = 0x50;

            // mov eax, [forward_page + 0xd00 + 4]      ;恢复eax
            forward_page_temp[i++] = 0xa1;
            *(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint + 0xd00 + 4;
            i += 4;



            // 解锁
            // push eax
            forward_page_temp[i++] = 0x50;
            // mov eax, 0
            forward_page_temp[i++] = 0xb8;
            *(uint32_t*)&forward_page_temp[i] = 0;
            i += 4;
            // mov [forward_page + 0xc00], eax
            forward_page_temp[i++] = 0xa3;
            *(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint + 0xc00 + 0;
            i += 4;
            // pop eax
            forward_page_temp[i++] = 0x58;



            // 转回去继续执行
            forward_page_temp[i++] = 0xc3;        // ret
            break;
        }
        case Architecture::kAmd64: {
            if (instr_size < 14) {
                return false;
            }

            int i = 0;

            // GetCurrentThreadId
            // 首先获取线程id锁保证线程安全且简单支持嵌套重入
            forward_page_temp[i++] = 0x50;        // push rax
            forward_page_temp[i++] = 0x51;        // push rcx
            forward_page_temp[i++] = 0x52;        // push rdx
            forward_page_temp[i++] = 0x9c;        // pushfq


            // GetCurrentThreadId
            // mov rax, qword ptr gs:[48h]
            forward_page_temp[i++] = 0x65;
            forward_page_temp[i++] = 0x48;
            forward_page_temp[i++] = 0x8b;
            forward_page_temp[i++] = 0x04;
            forward_page_temp[i++] = 0x25;
            *(uint32_t*)&forward_page[i] = 0x48;
            i += 4;


            // mov rdx, forward_page_uint + 0xc00
            forward_page_temp[i++] = 0x48;
            forward_page_temp[i++] = 0xba;
            *(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0xc00;
            i += 8;

            // 直接检查是否嵌套重入，是则是从callback再次回调到当前函数的，直接执行原函数流程
            // cmp rax, [rdx]
            forward_page_temp[i++] = 0x48;
            forward_page_temp[i++] = 0x3b;
            forward_page_temp[i++] = 0x02;

            // jne _retry
            forward_page_temp[i++] = 0x75;
            forward_page_temp[i++] = 4 + m_old_instr.size() + 14;      // 跳过原指令执行

            forward_page_temp[i++] = 0x9d;        // popfq
            forward_page_temp[i++] = 0x5a;        // pop rdx
            forward_page_temp[i++] = 0x59;        // pop rcx
            forward_page_temp[i++] = 0x58;        // pop rax

            memcpy(&forward_page_temp[i], m_old_instr.data(), m_old_instr.size());
            i += m_old_instr.size();

            // 跳回原函数正常执行
            i += MakeJmp(arch, &forward_page_temp[i], 0, forward_page_uint + i, hook_addr + instr_size);



            // 抢占锁，ecx保持为当前线程id
            // mov rcx, rax
            forward_page_temp[i++] = 0x48;
            forward_page_temp[i++] = 0x89;
            forward_page_temp[i++] = 0xc1;

        // _retry:
            // xor eax, eax
            forward_page_temp[i++] = 0x31;
            forward_page_temp[i++] = 0xc0;


            // lock cmpxchg qword ptr ds:[rdx], rcx
            forward_page_temp[i++] = 0xf0;
            forward_page_temp[i++] = 0x48;
            forward_page_temp[i++] = 0x0f;
            forward_page_temp[i++] = 0xb1;
            forward_page_temp[i++] = 0x0a;
            

            // 上锁成功，直接继续
            // je _end
            forward_page_temp[i++] = 0x74;
            forward_page_temp[i++] = 0x02;      // +2

            // jmp _retry
            forward_page_temp[i++] = 0xeb;
            forward_page_temp[i++] = 0xf5;      // -11

        // _end:
            forward_page_temp[i++] = 0x9d;        // popfd
            forward_page_temp[i++] = 0x5a;        // pop rdx
            forward_page_temp[i++] = 0x59;        // pop ecx
            forward_page_temp[i++] = 0x58;        // pop eax


            

            forward_page_temp[i++] = 0x54;        // push rsp

            // 提前压入转回地址，以便HookCallback能够修改
            forward_page_temp[i++] = 0x68;        // push low_addr
            *(uint32_t*)&forward_page_temp[i] = ((uint64_t)hook_addr + instr_size) & 0xffffffff;
            i += 4;
            forward_page_temp[i++] = 0xc7;        // mov dword ptr ss:[rsp+4], highAddr
            forward_page_temp[i++] = 0x44;
            forward_page_temp[i++] = 0x24;
            forward_page_temp[i++] = 0x04;
            *(uint32_t*)&forward_page_temp[i] = ((uint64_t)hook_addr + instr_size) >> 32;
            i += 4;


            // push forward_page_low
            forward_page_temp[i++] = 0x68;
            *(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint;
            i += 4;
            forward_page_temp[i++] = 0xc7;        // mov dword ptr ss:[rsp+4], forwardPageHigh
            forward_page_temp[i++] = 0x44;
            forward_page_temp[i++] = 0x24;
            forward_page_temp[i++] = 0x04;
            *(uint32_t*)&forward_page_temp[i] = forward_page_uint >> 32;
            i += 4;


            forward_page_temp[i++] = 0x50;        // push rax
            forward_page_temp[i++] = 0x51;        // push rcx
            forward_page_temp[i++] = 0x52;        // push rdx
            forward_page_temp[i++] = 0x53;        // push rbx
            forward_page_temp[i++] = 0x54;        // push rsp
            forward_page_temp[i++] = 0x55;        // push rbp
            forward_page_temp[i++] = 0x56;        // push rsi
            forward_page_temp[i++] = 0x57;        // push rdi
            forward_page_temp[i++] = 0x41;        // push r8
            forward_page_temp[i++] = 0x50;
            forward_page_temp[i++] = 0x41;        // push r9
            forward_page_temp[i++] = 0x51;
            forward_page_temp[i++] = 0x41;        // push r10
            forward_page_temp[i++] = 0x52;
            forward_page_temp[i++] = 0x41;        // push r11
            forward_page_temp[i++] = 0x53;
            forward_page_temp[i++] = 0x41;        // push r12
            forward_page_temp[i++] = 0x54;
            forward_page_temp[i++] = 0x41;        // push r13
            forward_page_temp[i++] = 0x55;
            forward_page_temp[i++] = 0x41;        // push r14
            forward_page_temp[i++] = 0x56;
            forward_page_temp[i++] = 0x41;        // push r15
            forward_page_temp[i++] = 0x57;
            forward_page_temp[i++] = 0x9c;        // pushfq


            // 遵循x64调用约定，为当前函数的使用提前分配栈空间
            forward_page_temp[i++] = 0x48;        // sub rsp, 28
            forward_page_temp[i++] = 0x83;
            forward_page_temp[i++] = 0xec;
            forward_page_temp[i++] = 0x20;



            // 传递参数
            forward_page_temp[i++] = 0x48;        // lea rcx, [rsp+20]      ; context
            forward_page_temp[i++] = 0x8d;
            forward_page_temp[i++] = 0x4c;
            forward_page_temp[i++] = 0x24;
            forward_page_temp[i++] = 0x20;



            forward_page_temp[i++] = 0x48;        // mov rax, addr
            forward_page_temp[i++] = 0xb8;
            *(uint64_t*)&forward_page_temp[i] = (uint64_t)callback;
            i += 8;

            forward_page_temp[i++] = 0xff;        // call rax
            forward_page_temp[i++] = 0xd0;

            // 先保存callback的返回值
            // mov [forward_page + 0xd00 + 0], al
            forward_page_temp[i++] = 0xa2;
            *(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0xd00 + 0;
            i += 8;


            // 传递参数
            forward_page_temp[i++] = 0x48;        // add rsp, 28
            forward_page_temp[i++] = 0x83;
            forward_page_temp[i++] = 0xc4;
            forward_page_temp[i++] = 0x20;


            forward_page_temp[i++] = 0x9d;        // popfq
            forward_page_temp[i++] = 0x41;        // pop r15
            forward_page_temp[i++] = 0x5f;
            forward_page_temp[i++] = 0x41;        // pop r14
            forward_page_temp[i++] = 0x5e;
            forward_page_temp[i++] = 0x41;        // pop r13
            forward_page_temp[i++] = 0x5d;
            forward_page_temp[i++] = 0x41;        // pop r12
            forward_page_temp[i++] = 0x5c;
            forward_page_temp[i++] = 0x41;        // pop r11
            forward_page_temp[i++] = 0x5b;
            forward_page_temp[i++] = 0x41;        // pop r10
            forward_page_temp[i++] = 0x5a;
            forward_page_temp[i++] = 0x41;        // pop r9
            forward_page_temp[i++] = 0x59;
            forward_page_temp[i++] = 0x41;        // pop r8
            forward_page_temp[i++] = 0x58;
            forward_page_temp[i++] = 0x5f;        // pop rdi
            forward_page_temp[i++] = 0x5e;        // pop rsi
            forward_page_temp[i++] = 0x5d;        // pop rbp
            forward_page_temp[i++] = 0x5c;        // pop rsp
            forward_page_temp[i++] = 0x5b;        // pop rbx
            forward_page_temp[i++] = 0x5a;        // pop rdx
            forward_page_temp[i++] = 0x59;        // pop rcx
            forward_page_temp[i++] = 0x58;        // pop rax


            forward_page_temp[i++] = 0x48;        // add esp, 跳过forward_page
            forward_page_temp[i++] = 0x83;
            forward_page_temp[i++] = 0xc4;
            forward_page_temp[i++] = 0x08;



            // 在原指令执行前还原所有环境，包括压入的retAddr
            // 要用rax，先存到内存里
            // mov [forward_page + 0xd00 + 8], rax
            forward_page_temp[i++] = 0x48;
            forward_page_temp[i++] = 0xa3;
            *(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0xd00 + 8;
            i += 8;

            // 接下来把ret_addr存到内存里
            forward_page_temp[i++] = 0x58;        // pop rax        ;弹出压入的ret_addr
            // mov [forward_page + 0xd00 + 16], rax
            forward_page_temp[i++] = 0x48;
            forward_page_temp[i++] = 0xa3;
            *(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0xd00 + 16;
            i += 8;

            // 在执行前恢复rsp
            forward_page_temp[i++] = 0x5c;        // pop rsp，弹出压入的esp


            // 拿到callback的返回值
            // mov al, [forward_page + 0xd00 + 0]
            forward_page_temp[i++] = 0xa0;
            *(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0xd00 + 0;
            i += 8;


            forward_page_temp[i++] = 0x9c;      // pushfd
            // cmp al, 0
            forward_page_temp[i++] = 0x3c;
            forward_page_temp[i++] = 0x00;

            // mov rax, [forward_page + 0xd00 + 8]，恢复rax
            forward_page_temp[i++] = 0x48;
            forward_page_temp[i++] = 0xa1;
            *(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0xd00 + 8;
            i += 8;

            // je _skip_exec_old_insrt
            forward_page_temp[i++] = 0x74;
            forward_page_temp[i++] = 1 + m_old_instr.size() + 2;

            forward_page_temp[i++] = 0x9d;      // popfd
            // 执行原指令
            memcpy(&forward_page_temp[i], m_old_instr.data(), m_old_instr.size());
            i += m_old_instr.size();
            // jmp _next_exec_old_insrt
            forward_page_temp[i++] = 0xeb;
            forward_page_temp[i++] = 0x01;      // +1

        // _skip_exec_old_insrt:
            forward_page_temp[i++] = 0x9d;      // popfd
        // _next_exec_old_insrt:


            


            // 恢复ret_addr环境
            // mov [forward_page + 0xd00 + 8], rax，还是先保存rax
            forward_page_temp[i++] = 0x48;
            forward_page_temp[i++] = 0xa3;
            *(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0xd00 + 8;
            i += 8;

            // mov rax, [forward_page + 0xd00 + 16]，保存的ret_addr
            forward_page_temp[i++] = 0x48;
            forward_page_temp[i++] = 0xa1;
            *(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0xd00 + 16;
            i += 8;
            // push rax
            forward_page_temp[i++] = 0x50;

            // mov rax, [forward_page + 0xd00 + 8]，恢复eax
            forward_page_temp[i++] = 0x48;
            forward_page_temp[i++] = 0xa1;
            *(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0xd00 + 8;
            i += 8;



            // 解锁
            // push rax
            forward_page_temp[i++] = 0x50;

            // mov rax, 0
            forward_page_temp[i++] = 0x48; 
            forward_page_temp[i++] = 0xc7;
            forward_page_temp[i++] = 0xc0;
            *(uint32_t*)&forward_page_temp[i] = 0;
            i += 4;

            // mov [forward_page + 0xc00 + 0], rax      ;解锁
            forward_page_temp[i++] = 0x48;
            forward_page_temp[i++] = 0xa3;
            *(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0xc00 + 0;
            i += 8;

            // pop rax
            forward_page_temp[i++] = 0x58;



            // 转回去继续执行
            forward_page_temp[i++] = 0xc3;        // ret
            break;
        }
        }
        m_process->WriteMemory(m_forward_page, forward_page_temp, forward_page_size);

        // 为目标地址挂hook
        m_hook_addr = hook_addr;

        MakeJmp(arch, &jmp_instr[0], instr_size, hook_addr, m_forward_page);
        m_process->WriteMemory(hook_addr, &jmp_instr[0], instr_size, true);
        return true;
    }


    /*
    * 在函数头部接管调用，不会执行原函数，回调函数原型是原函数的函数原型
    */
    bool InstallFake(uint64_t hook_addr, size_t instr_size, uint64_t callback, Architecture arch = Architecture::kCurrentRunning) {
        Uninstall();

        if (arch == Architecture::kCurrentRunning) arch = GetCurrentRunningArch();

        m_old_instr.resize(instr_size);
        if (!m_process->ReadMemory(hook_addr, m_old_instr.data(), instr_size)) {
            return false;
        }

        m_hook_addr = hook_addr;

        auto jmp_instr = m_old_instr;

        MakeJmp(arch, &jmp_instr[0], instr_size, hook_addr, callback);
        m_process->WriteMemory(hook_addr, &jmp_instr[0], instr_size, true);
    }

    /*
    * 卸载Hook
    */
    void Uninstall() {
        if (m_hook_addr) {
            m_process->WriteMemory(m_hook_addr, m_old_instr.data(), m_old_instr.size(), true);
            m_hook_addr = 0;
        }
        if (m_forward_page) {
            m_process->FreeMemory(m_forward_page);
            m_forward_page = 0;
        }
    }

    uint64_t GetForwardPage() {
        return m_forward_page;
    }


private:
    Architecture GetCurrentRunningArch() {
        Architecture arch;
        if (m_process->IsX86()) {
            arch = Architecture::kX86;
        }
        else {
            arch = Architecture::kAmd64;
        }
        return arch;
    }

    void MonitorWriteCallback(uint64_t* callback) {
        *callback = m_forward_page + 0x1000;
        auto func_size = (uint64_t)MonitorCallbackEnd - (uint64_t)MonitorCallbackStart;
        if (func_size > 0x1000) {
            func_size = 0x1000;
        }
        m_process->WriteMemory(m_forward_page + 0x1000, MonitorCallbackStart, func_size);
    }

private:
    Process* m_process;
    uint64_t m_hook_addr;
    uint64_t m_forward_page;
    std::vector<char> m_old_instr;

private:
    static uint64_t GetJmpOffset(uint64_t instr_addr, size_t instr_size, uint64_t jmp_addr) {
        return jmp_addr - instr_addr - instr_size;
    }

    static uint64_t MakeJmp(Architecture arch, void* buf, uint64_t instr_size, uint64_t cur_addr, uint64_t jmp_addr) {
        uint8_t* _buf = (uint8_t*)buf;
        switch (arch) {
        case Architecture::kX86: {
            if (instr_size == 0) instr_size = 5;
            _buf[0] = 0xe9;        // jmp
            *(uint32_t*)&_buf[1] = GetJmpOffset(cur_addr, 5, jmp_addr);

            for (int i = 5; i < instr_size; i++) {
                _buf[i] = 0xcc;        // int 3
            }
            break;
        }
        case Architecture::kAmd64: {
            if (instr_size == 0) instr_size = 14;
            _buf[0] = 0x68;        // push low_addr
            *(uint32_t*)&_buf[1] = (uint64_t)jmp_addr & 0xffffffff;
            _buf[5] = 0xc7;        // mov dword ptr ss:[rsp+4], high_addr
            _buf[6] = 0x44;
            _buf[7] = 0x24;
            _buf[8] = 0x04;
            *(uint32_t*)&_buf[9] = (uint64_t)jmp_addr >> 32;
            _buf[13] = 0xc3;        // ret

            for (int i = 14; i < instr_size; i++) {
                _buf[i] = 0xcc;        // int 3
            }
            break;
        }
        }
        return instr_size;
    }


    static void MonitorCallbackStart(uint64_t context) {

    }

    static void MonitorCallbackEnd() { }


#define GET_CURRENT_ADDR { 0xe8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x48, 0x8c, 0xc0, 0x05 }         // call next;    next: pop eax/rax;    add eax/rax, 5;


#define GET_KERNEL32_IMAGE_BASE { 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x8B, 0x40, 0x0C, 0x8B, 0x40, 0x0C, 0x8B, 0x00, 0x8B, 0x00, 0x8B, 0x40, 0x18 }
    /* 定位kernel32
    mov eax, dword ptr fs : [30h]     ;ָ指向PEB结构
    mov eax, dword ptr[eax + 0Ch]     ;ָ指向LDR Ptr32 _PEB_LDR_DATA
    mov eax, dword ptr[eax + 0Ch]     ;指向InLoadOrderModuleList _LIST_ENTRY
    mov eax, dword ptr[eax]         ;移动_LIST_ENTRY
    mov eax, dword ptr[eax]         ;ָ指向Kernel32
    mov eax, dword ptr[eax + 18h]     ;指向DllBase基址
    ;ret
    */

};

} // namespace Geek

#endif // GEEK_HOOK_INLINE_HOOK_H_
