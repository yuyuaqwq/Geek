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

    enum class Mode {
        kNormal,
        kTakeOver,
    };

    struct HookContextX86 {
        uint32_t* const stack;
        uint32_t esp;
        uint32_t jmp_addr;
        uint32_t forward_page_base;
        uint32_t hook_addr;
        uint32_t old_stack_top;     // pop
        uint32_t reserve[10];

        uint32_t eax;
        uint32_t ecx;
        uint32_t edx;
        uint32_t ebx;
        uint32_t esp_invalid;
        uint32_t ebp;
        uint32_t esi;
        uint32_t edi;
        uint32_t eflags;
    };
    struct HookContextAmd64 {
        uint64_t* const stack;
        uint64_t rsp;
        uint64_t jmp_addr;
        uint64_t forward_page_base;
        uint64_t hook_addr;
        uint64_t old_stack_top;     // pop
        uint64_t reserve[10];

        uint64_t rax;
        uint64_t rcx;
        uint64_t rdx;
        uint64_t rbx;
        uint64_t rbp;
        uint64_t rsp_invalid;
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
        uint64_t rflags;
    };

    // 位于Forwa 0xc00 ~ 0xcff 处的结构体
    struct HookContextForwardInfoX86 {
        uint32_t thread_id_lock;
    };

    struct HookContextForwardInfoAmd64 {
        uint64_t thread_id_lock;
    };
    
    

    typedef bool (__fastcall *HookCallbackX86)(HookContextX86* context, HookContextForwardInfoX86* forward_info);
    typedef bool (*HookCallbackAmd64)(HookContextAmd64* context, HookContextForwardInfoAmd64* forward_info);

public:
    explicit InlineHook(Process* process = nullptr) : m_process{ process }, m_hook_addr{ 0 }, m_forward_page{ 0 }{ }
    ~InlineHook() {

    }

public:

    /*
    * 安装通用转发调用Hook
        * 可以在任意位置hook，参数为HookContext*，具体类型因处理器架构而异
        * 支持在回调函数中调用原函数
        * 回调函数是线程安全的(加锁，如果出现死锁请考虑此因素)
    * 
    * 被hook处用于覆写的指令不能存在相对偏移指令
        * 如0xe8、0xe9(可解决思路：在转发页面将hook处指令还原，但修改hook处的后继指令为再度跳转，在再度跳转中还原hook并还原后继指令，再跳回后继指令处执行，即可复用hook)
    * 
    * x86要求instr_size>=5，x64要求instr_size>=14，且instr_size不能大于255
    * 
    * forward_page是转发页面，至少需要0x2000，前0x2000不可覆写
        * 可以指定较多的空间，便于交互数据
    * 
    * 跨进程请关闭/GS(安全检查)，避免生成__security_cookie插入代码
    * 
    * 如果需要修改rsp或者jmp_addr，注意堆栈平衡
        * 默认情况下jmp_addr是指向被hook处的下一行指令
        * push和pop顺序为    push esp -> push jmp_addr -> push xxx    call    pop xxx -> pop&save jmp_addr -> pop esp -> 是否执行原指令 -> get&push jmp_addr -> ret
    * 
    * 若pop_stack_top为true
        * 在调用回调时不会有额外栈帧，可以用于需要输出栈回溯的场景
        * 会在调用回调前将当前栈顶的值pop到context->old_stack_top
        * 而context->stack[0]会存储回调函数返回的地址
    * 
    * 实现接管：
        * 在函数起始hook
        * pop_stack_top = true
        * callback中 context->esp += 4 / context->rsp += 8;	// 跳过外部call到该函数的返回地址
            * 注：x86下还需要根据调用约定来确定是否需要额外加上参数数量字节，比如stdcall就需要 + count * 4，但cdecl不需要。
        * callback中指定 jmp_addr = context->old_stack_top;      // 直接返回到调用被hook函数的调用处
        * callback中返回false      // 不执行原指令
        *
    *
    * 实现监视：
        * 与接管基本一致
        * 需要获取原函数执行结果
            * 直接在callback中再次调用原函数以获取其运行结果
            * 返回false        // 不执行原指令
        * 不需要获取原函数执行结果
            * 不修改esp/rsp以及jmp_addr
            * 返回true
    * 
    * 栈回溯隐藏
        * 函数头部hook
        * pop_stack_top = true
        * 原理就是将call callback时留在栈上的，返回到转发页面的地址临时修改为原调用处的返回地址
        * 回调函数起始：
            * auto cur_ret = context->stack[0];
            * context->stack[0] = context->old_stack_top;
        * 回调函数返回：
            * context->stack[0] = cur_ret;
    *
    * Amd64下构建栈帧时应该是以16字节对齐的，否则部分指令(浮点等)可能会异常
    */

    bool Install(uint64_t hook_addr, size_t instr_size, uint64_t callback, bool pop_stack_top = false, Architecture arch = Architecture::kCurrentRunning,
        uint64_t forward_page_size = 0x2000
    ) {
        if (instr_size > 255) {
            return false;
        }

        Uninstall();
        if (forward_page_size < 0x2000) {
            forward_page_size = 0x2000;
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
        
        std::vector<uint8_t> jmp_instr(instr_size);
        if (arch == Architecture::kCurrentRunning) arch = GetCurrentRunningArch();

        switch (arch) {
        case Architecture::kX86: {
            if (instr_size < 5) {
                return false;
            }

            int i = 0;

            // 加可重入锁
            {
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
                std::vector<uint8_t> temp;
                MakeJmp(arch, &temp, forward_page_uint + i, hook_addr + instr_size);
                memcpy(&forward_page_temp[i], &temp[0], temp.size());
                i += temp.size();

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
            }

            // 保存上下文环境
            {
                forward_page_temp[i++] = 0x50;        // push eax
                forward_page_temp[i++] = 0x51;        // push ecx

                // mov ecx, forward_page + 0x1000
                forward_page_temp[i++] = 0xb9;
                *(uint32_t*)&forward_page_temp[i] = forward_page_uint + 0x1000;
                i += 4;

                // 压入原stack，跳过前面push的eax和ecx
                // lea eax, [esp+0x8]
                forward_page_temp[i++] = 0x8d;
                forward_page_temp[i++] = 0x44;
                forward_page_temp[i++] = 0x24;
                forward_page_temp[i++] = 0x8;
                // mov [ecx], eax
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0x01;

                // 实际上是压入esp
                // mov [ecx+4], eax
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0x41;
                forward_page_temp[i++] = 0x04;


                // mov eax, hook_addr + instr_size
                forward_page_temp[i++] = 0xb8;
                *(uint32_t*)&forward_page_temp[i] = (uint32_t)hook_addr + instr_size;
                i += 4;
                // mov [ecx+0x8], eax
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0x41;
                forward_page_temp[i++] = 0x8;

                // mov eax, forward_page
                forward_page_temp[i++] = 0xb8;
                *(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint;
                i += 4;
                // mov [ecx+0xc], rax
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0x41;
                forward_page_temp[i++] = 0xc;

                // mov eax, hook_addr
                forward_page_temp[i++] = 0xb8;
                *(uint32_t*)&forward_page_temp[i] = (uint32_t)hook_addr;
                i += 4;
                // mov [ecx+0x10], eax
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0x41;
                forward_page_temp[i++] = 0x10;

                // pop eax      // 这里其实是ecx
                forward_page_temp[i++] = 0x58;
                // mov [ecx+0x44], eax
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0x41;
                forward_page_temp[i++] = 0x44;

                // pop eax
                forward_page_temp[i++] = 0x58;
                // mov [ecx+0x40], eax
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0x41;
                forward_page_temp[i++] = 0x40;

                // mov [ecx+0x48], edx
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0x51;
                forward_page_temp[i++] = 0x48;

                // mov [ecx+0x4c], ebx
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0x59;
                forward_page_temp[i++] = 0x4c;

                // mov [ecx+0x50], esp
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0x61;
                forward_page_temp[i++] = 0x50;

                // mov [ecx+0x54], ebp
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0x69;
                forward_page_temp[i++] = 0x54;

                // mov [ecx+0x58], esi
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0x71;
                forward_page_temp[i++] = 0x58;

                // mov [ecx+0x5c], edi
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0x79;
                forward_page_temp[i++] = 0x5c;

                forward_page_temp[i++] = 0x9c;        // pushfd
                forward_page_temp[i++] = 0x58;        // pop eax
                // mov [ecx+0x60], eax
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0x41;
                forward_page_temp[i++] = 0x60;

            }
            
            if (pop_stack_top) {
                // pop rax
                forward_page_temp[i++] = 0x58;
                // 保存旧栈顶
                // mov [forward_page + 0x1000 + 0x14], eax
                forward_page_temp[i++] = 0xa3;
                *(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint + 0x1000 + 0x14;
                i += 4;
            }

            // 准备调用
            // 传递参数
            // 使用fastcall，参数已在ecx中

            forward_page_temp[i++] = 0xe8;        // call callback
            *(uint32_t*)&forward_page_temp[i] = GetInstrOffset((forward_page_uint + i - 1), 5, callback);
            i += 4;

            // 先把callback返回值保存起来
            // mov [forward_page + 0xd00 + 0], al
            forward_page_temp[i++] = 0xa2;
            *(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint + 0xd00 + 0;
            i += 4;

            // 恢复上下文环境
            {
                // mov ecx, forward_page + 0x1000
                forward_page_temp[i++] = 0xb9;
                *(uint32_t*)&forward_page_temp[i] = forward_page_uint + 0x1000;
                i += 4;

                // mov eax, [ecx + 0x60]
                forward_page_temp[i++] = 0x8b;
                forward_page_temp[i++] = 0x41;
                forward_page_temp[i++] = 0x60;

                forward_page_temp[i++] = 0x50;        // push eax
                forward_page_temp[i++] = 0x9d;        // popfd

                // mov edx, [ecx + 0x48]
                forward_page_temp[i++] = 0x8b;
                forward_page_temp[i++] = 0x51;
                forward_page_temp[i++] = 0x48;

                // mov ebx, [ecx + 0x4c]
                forward_page_temp[i++] = 0x8b;
                forward_page_temp[i++] = 0x59;
                forward_page_temp[i++] = 0x4c;

                // mov esp, [ecx + 0x50]
                forward_page_temp[i++] = 0x8b;
                forward_page_temp[i++] = 0x61;
                forward_page_temp[i++] = 0x50;

                // mov ebp, [ecx + 0x54]
                forward_page_temp[i++] = 0x8b;
                forward_page_temp[i++] = 0x69;
                forward_page_temp[i++] = 0x54;

                // mov esi, [ecx + 0x58]
                forward_page_temp[i++] = 0x8b;
                forward_page_temp[i++] = 0x71;
                forward_page_temp[i++] = 0x58;

                // mov edi, [ecx + 0x5c]
                forward_page_temp[i++] = 0x8b;
                forward_page_temp[i++] = 0x79;
                forward_page_temp[i++] = 0x5c;


                // mov ecx, [forward_page + 0x1000 + 0x44]
                forward_page_temp[i++] = 0x8b;
                forward_page_temp[i++] = 0x0d;
                *(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint + 0x1000 + 0x44;
                i += 4;

                // mov eax, [forward_page + 0x1000 + 0x40]
                forward_page_temp[i++] = 0xa1;
                *(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint + 0x1000 + 0x40;
                i += 4;
            }
            

            // 在原指令执行前还原所有环境，包括压入的jmp_addr
            // 要用eax，先存到内存里
            // mov [forward_page + 0xd00 + 4], eax
            forward_page_temp[i++] = 0xa3;
            *(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint + 0xd00 + 4;
            i += 4;

            // 执行前设置hook回调中可能修改的esp
            // mov esp, [forward_page + 0x1000 + 4]
            forward_page_temp[i++] = 0x8b;
            forward_page_temp[i++] = 0x25;
            *(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint + 0x1000 + 4;
            i += 4;


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
            
            // 恢复jmp_addr环境
            // mov [forward_page + 0xd00 + 4], eax      ;还是先保存eax
            forward_page_temp[i++] = 0xa3;
            *(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint + 0xd00 + 4;
            i += 4;

            // mov eax, [forward_page + 0x1000 + 0x8]      ;拿到jmp_addr
            forward_page_temp[i++] = 0xa1;
            *(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint + 0x1000 + 0x8;
            i += 4;
            // push eax     ; 压入ret时返回的地址
            forward_page_temp[i++] = 0x50;

            // mov eax, [forward_page + 0xd00 + 4]      ;恢复eax
            forward_page_temp[i++] = 0xa1;
            *(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint + 0xd00 + 4;
            i += 4;


            // 解锁
            {
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
            }


            // 转回去继续执行
            forward_page_temp[i++] = 0xc3;        // ret
            break;
        }
        case Architecture::kAmd64: {
            if (instr_size < 14) {
                return false;
            }

            int i = 0;

            // 加可重入锁
            {
                // GetCurrentThreadId
                // 首先获取线程id，保证线程安全且简单支持嵌套重入
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
                std::vector<uint8_t> temp;
                MakeJmp(arch, &temp, forward_page_uint + i, hook_addr + instr_size);
                memcpy(&forward_page_temp[i], &temp[0], temp.size());
                i += temp.size();



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
            }

            // 保存上下文环境
            {
                forward_page_temp[i++] = 0x50;        // push rax
                forward_page_temp[i++] = 0x51;        // push rcx

                // mov rax, forward_page + 0x1000
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0xb8;
                *(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0x1000;
                i += 8;
                // mov rcx, rax
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0xc1;


                // 压入原stack，跳过前面push的rax和rcx
                // lea rax, [rsp+0x10]
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x8d;
                forward_page_temp[i++] = 0x44;
                forward_page_temp[i++] = 0x24;
                forward_page_temp[i++] = 0x10;
                // mov [rcx], rax
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0x01;

                // 实际上是压入rsp
                // mov [rcx+8], rax
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0x41;
                forward_page_temp[i++] = 0x08;

                // 提前压入转回地址，以便HookCallback能够修改
                // mov rax, hook_addr + instr_size
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0xb8;
                *(uint64_t*)&forward_page_temp[i] = (uint64_t)hook_addr + instr_size;
                i += 8;
                // mov [rcx+0x10], rax
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0x41;
                forward_page_temp[i++] = 0x10;

                // mov rax, forward_page
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0xb8;
                *(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint;
                i += 8;
                // mov [rcx+0x18], rax
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0x41;
                forward_page_temp[i++] = 0x18;

                // mov rax, hook_addr
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0xb8;
                *(uint64_t*)&forward_page_temp[i] = (uint64_t)hook_addr;
                i += 8;
                // mov [rcx+0x20], rax
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0x41;
                forward_page_temp[i++] = 0x20;

                // pop rax      // 这里其实是rcx
                forward_page_temp[i++] = 0x58;
                // mov [rcx+0x88], rax
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0x81;
                *(uint32_t*)&forward_page_temp[i] = 0x88;
                i += 4;

                // pop rax
                forward_page_temp[i++] = 0x58;
                // mov [rcx+0x80], rax
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0x81;
                *(uint32_t*)&forward_page_temp[i] = 0x80;
                i += 4;


                // mov [rcx+0x90], rdx
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0x91;
                *(uint32_t*)&forward_page_temp[i] = 0x90;
                i += 4;


                // mov [rcx+0x98], rbx
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0x99;
                *(uint32_t*)&forward_page_temp[i] = 0x98;
                i += 4;


                // mov [rcx+0xa0], rsp
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0xa1;
                *(uint32_t*)&forward_page_temp[i] = 0xa0;
                i += 4;


                // mov [rcx+0xa8], rbp
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0xa9;
                *(uint32_t*)&forward_page_temp[i] = 0xa8;
                i += 4;

                // mov [rcx+0xb0], rsi
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0xb1;
                *(uint32_t*)&forward_page_temp[i] = 0xb0;
                i += 4;

                // mov [rcx+0xb8], rdi
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0xb9;
                *(uint32_t*)&forward_page_temp[i] = 0xb8;
                i += 4;


                // mov [rcx+0xc0], r8
                forward_page_temp[i++] = 0x4c;
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0x81;
                *(uint32_t*)&forward_page_temp[i] = 0xc0;
                i += 4;

                // mov [rcx+0xc8], r9
                forward_page_temp[i++] = 0x4c;
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0x89;
                *(uint32_t*)&forward_page_temp[i] = 0xc8;
                i += 4;

                // mov [rcx+0xd0], r10
                forward_page_temp[i++] = 0x4c;
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0x91;
                *(uint32_t*)&forward_page_temp[i] = 0xd0;
                i += 4;

                // mov [rcx+0xd8], r11
                forward_page_temp[i++] = 0x4c;
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0x99;
                *(uint32_t*)&forward_page_temp[i] = 0xd8;
                i += 4;

                // mov [rcx+0xe0], r12
                forward_page_temp[i++] = 0x4c;
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0xa1;
                *(uint32_t*)&forward_page_temp[i] = 0xe0;
                i += 4;

                // mov [rcx+0xe8], r13
                forward_page_temp[i++] = 0x4c;
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0xa9;
                *(uint32_t*)&forward_page_temp[i] = 0xe8;
                i += 4;

                // mov [rcx+0xf0], r14
                forward_page_temp[i++] = 0x4c;
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0xb1;
                *(uint32_t*)&forward_page_temp[i] = 0xf0;
                i += 4;

                // mov [rcx+0xf8], r15
                forward_page_temp[i++] = 0x4c;
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0xb9;
                *(uint32_t*)&forward_page_temp[i] = 0xf8;
                i += 4;

                forward_page_temp[i++] = 0x9c;        // pushfq
                forward_page_temp[i++] = 0x58;        // pop rax
                // mov [rcx+0x100], rax
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0x81;
                *(uint32_t*)&forward_page_temp[i] = 0x100;
                i += 4;
            }

            // 遵循x64调用约定，为当前函数的使用提前分配栈空间
            // 因为栈上没有放东西，可以不构建这个
            //forward_page_temp[i++] = 0x48;        // sub rsp, 20
            //forward_page_temp[i++] = 0x83;
            //forward_page_temp[i++] = 0xec;
            //forward_page_temp[i++] = 0x20;

            // 参数即rcx，在保存上下文时已经设置了

            if (pop_stack_top) {
                // pop rax
                forward_page_temp[i++] = 0x58;
                // 保存旧栈顶
                // mov [forward_page + 0x1000 + 0x28], rax
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0xa3;
                *(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0x1000 + 0x28;
                i += 8;
            }

            // 强制使栈16字节对齐
            {
                // mov rax, rsp
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0xe0;

                // and rax, 0x8
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x83;
                forward_page_temp[i++] = 0xe0;
                forward_page_temp[i++] = 0x08;

                // sub rsp, rax
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x29;
                forward_page_temp[i++] = 0xc4;


                // 把对齐值保存起来
                // mov [forward_page + 0xd00 + 0x18], rax
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0xa3;
                *(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0xd00 + 0x18;
                i += 8;
            }



            // 调用
            forward_page_temp[i++] = 0x48;        // mov rax, addr
            forward_page_temp[i++] = 0xb8;
            *(uint64_t*)&forward_page_temp[i] = (uint64_t)callback;
            i += 8;
            // jmp rax
            //forward_page_temp[i++] = 0xff;
            //forward_page_temp[i++] = 0xe0;
            // call rax
            forward_page_temp[i++] = 0xff;
            forward_page_temp[i++] = 0xd0;


            // 先保存callback的返回值
            // mov [forward_page + 0xd00 + 0], al
            forward_page_temp[i++] = 0xa2;
            *(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0xd00 + 0;
            i += 8;


            // 恢复栈对齐
            {
                // mov rax, [forward_page + 0xd00 + 0x18]
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0xa1;
                *(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0xd00 + 0x18;
                i += 8;
                // add rsp, rax
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x01;
                forward_page_temp[i++] = 0xc4;
            }


        // _recovery_stack:
            // 恢复传递参数的栈
            //forward_page_temp[i++] = 0x48;        // add rsp, 20
            //forward_page_temp[i++] = 0x83;
            //forward_page_temp[i++] = 0xc4;
            //forward_page_temp[i++] = 0x20;


            // 恢复上下文环境
            {
                // mov rax, forward_page + 0x1000
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0xb8;
                *(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0x1000;
                i += 8;
                // mov rcx, rax
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0xc1;

                // mov rax, [rcx + 0x100]
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x8b;
                forward_page_temp[i++] = 0x81;
                *(uint32_t*)&forward_page_temp[i] = 0x100;
                i += 4;
                forward_page_temp[i++] = 0x50;        // push rax
                forward_page_temp[i++] = 0x9d;        // popfq


                // mov rdx, [rcx + 0x90]
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x8b;
                forward_page_temp[i++] = 0x91;
                *(uint32_t*)&forward_page_temp[i] = 0x90;
                i += 4;

                // mov rbx, [rcx + 0x98]
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x8b;
                forward_page_temp[i++] = 0x99;
                *(uint32_t*)&forward_page_temp[i] = 0x98;
                i += 4;

                // mov rsp, [rcx + 0xa0]
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x8b;
                forward_page_temp[i++] = 0xa1;
                *(uint32_t*)&forward_page_temp[i] = 0xa0;
                i += 4;

                // mov rbp, [rcx + 0xa8]
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x8b;
                forward_page_temp[i++] = 0xa9;
                *(uint32_t*)&forward_page_temp[i] = 0xa8;
                i += 4;

                // mov rsi, [rcx + 0xb0]
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x8b;
                forward_page_temp[i++] = 0xb1;
                *(uint32_t*)&forward_page_temp[i] = 0xb0;
                i += 4;

                // mov rdi, [rcx + 0xb8]
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x8b;
                forward_page_temp[i++] = 0xb9;
                *(uint32_t*)&forward_page_temp[i] = 0xb8;
                i += 4;


                // mov r8, [rcx + 0xc0]
                forward_page_temp[i++] = 0x4c;
                forward_page_temp[i++] = 0x8b;
                forward_page_temp[i++] = 0x81;
                *(uint32_t*)&forward_page_temp[i] = 0xc0;
                i += 4;

                // mov r9, [rcx + 0xc8]
                forward_page_temp[i++] = 0x4c;
                forward_page_temp[i++] = 0x8b;
                forward_page_temp[i++] = 0x89;
                *(uint32_t*)&forward_page_temp[i] = 0xc8;
                i += 4;

                // mov r10, [rcx + 0xd0]
                forward_page_temp[i++] = 0x4c;
                forward_page_temp[i++] = 0x8b;
                forward_page_temp[i++] = 0x91;
                *(uint32_t*)&forward_page_temp[i] = 0xd0;
                i += 4;

                // mov r11, [rcx + 0xd8]
                forward_page_temp[i++] = 0x4c;
                forward_page_temp[i++] = 0x8b;
                forward_page_temp[i++] = 0x99;
                *(uint32_t*)&forward_page_temp[i] = 0xd8;
                i += 4;

                // mov r12, [rcx + 0xe0]
                forward_page_temp[i++] = 0x4c;
                forward_page_temp[i++] = 0x8b;
                forward_page_temp[i++] = 0xa1;
                *(uint32_t*)&forward_page_temp[i] = 0xe0;
                i += 4;

                // mov r13, [rcx + 0xe8]
                forward_page_temp[i++] = 0x4c;
                forward_page_temp[i++] = 0x8b;
                forward_page_temp[i++] = 0xa9;
                *(uint32_t*)&forward_page_temp[i] = 0xe8;
                i += 4;

                // mov r14, [rcx + 0xf0]
                forward_page_temp[i++] = 0x4c;
                forward_page_temp[i++] = 0x8b;
                forward_page_temp[i++] = 0xb1;
                *(uint32_t*)&forward_page_temp[i] = 0xf0;
                i += 4;

                // mov r15, [rcx + 0xf8]
                forward_page_temp[i++] = 0x4c;
                forward_page_temp[i++] = 0x8b;
                forward_page_temp[i++] = 0xb9;
                *(uint32_t*)&forward_page_temp[i] = 0xf8;
                i += 4;


                // mov rax, [forward_page + 0x1000 + 0x88]
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0xa1;
                *(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0x1000 + 0x88;
                i += 8;
                // mov rcx, rax
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0x89;
                forward_page_temp[i++] = 0xc1;

                // mov rax, [forward_page + 0x1000 + 0x80]
                forward_page_temp[i++] = 0x48;
                forward_page_temp[i++] = 0xa1;
                *(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0x1000 + 0x80;
                i += 8;
            }


            // 在原指令执行前还原所有环境，包括保存的jmp_addr
            // 要用rax，先存到内存里
            // mov [forward_page + 0xd00 + 8], rax
            forward_page_temp[i++] = 0x48;
            forward_page_temp[i++] = 0xa3;
            *(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0xd00 + 8;
            i += 8;

            
            // 执行前设置hook回调中可能修改的rsp
            // mov rax, [forward_page + 0x1000 + 8]
            forward_page_temp[i++] = 0x48;
            forward_page_temp[i++] = 0xa1;
            *(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0x1000 + 8;
            i += 8;
            // mov rsp, rax
            forward_page_temp[i++] = 0x48;
            forward_page_temp[i++] = 0x89;
            forward_page_temp[i++] = 0xc4;


            // 准备执行原指令
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


            


            // 恢复jmp_addr环境
            // mov [forward_page + 0xd00 + 8], rax，还是先保存rax
            forward_page_temp[i++] = 0x48;
            forward_page_temp[i++] = 0xa3;
            *(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0xd00 + 8;
            i += 8;

            // mov rax, [forward_page + 0x1000 + 0x10]      ;拿到jmp_addr
            forward_page_temp[i++] = 0x48;
            forward_page_temp[i++] = 0xa1;
            *(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0x1000 + 0x10;
            i += 8;
            // push rax     ; 压入ret时返回的地址
            forward_page_temp[i++] = 0x50;

            // mov rax, [forward_page + 0xd00 + 8]，恢复eax
            forward_page_temp[i++] = 0x48;
            forward_page_temp[i++] = 0xa1;
            *(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint + 0xd00 + 8;
            i += 8;

            // 解锁
            {
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
            }

            // 转回去继续执行
            forward_page_temp[i++] = 0xc3;        // ret
            break;
        }
        }
        m_process->WriteMemory(m_forward_page, forward_page_temp, forward_page_size);

        // 为目标地址挂hook
        m_hook_addr = hook_addr;

        
        if (m_process->IsCur() && 
            (
                arch == Architecture::kX86 && instr_size <= 8 || 
                arch == Architecture::kAmd64 && instr_size <= 16
            )
        ) {
            DWORD old_protect;
            if (!m_process->SetMemoryProtect(hook_addr, 0x1000, PAGE_EXECUTE_READWRITE, &old_protect)) {
                return false;
            }
            // 通过原子指令进行hook，降低错误的概率
            bool success = true;
            switch (arch) {
            case Architecture::kX86: {
                MakeJmp(arch, &jmp_instr, hook_addr, m_forward_page);
                if (jmp_instr.size() < 8) {
                    jmp_instr.reserve(8);
                    memcpy(&jmp_instr[jmp_instr.size()], ((uint8_t*)hook_addr) + jmp_instr.size(), 8 - jmp_instr.size());
                }
                InterlockedExchange64((volatile long long*)hook_addr, *(LONGLONG*)&jmp_instr[0]);
                break;
            }
            case Architecture::kAmd64:
#ifdef _WIN64
                if (jmp_instr.size() < 16) {
                    jmp_instr.reserve(16);
                    memcpy(&jmp_instr[jmp_instr.size()], ((uint8_t*)hook_addr) + jmp_instr.size(), 16 - jmp_instr.size());
                }
                MakeJmp(arch, &jmp_instr, hook_addr, m_forward_page);
                uint8_t buf[16];
                memcpy(buf, (void*)hook_addr, 16);
                success = InterlockedCompareExchange128((volatile long long*)hook_addr, *(LONGLONG*)&jmp_instr[8], *(LONGLONG*)&jmp_instr[0], (long long*)buf);
#else
                success = false;
#endif
                break;
            }
            m_process->SetMemoryProtect(hook_addr, 0x1000, old_protect, &old_protect);
            if (success == false) return false;
        }
        else {
            MakeJmp(arch, &jmp_instr, hook_addr, m_forward_page);
            m_process->WriteMemory(hook_addr, &jmp_instr[0], instr_size, true);
        }
        return true;
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
    static uint64_t GetInstrOffset(uint64_t instr_addr, size_t instr_size, uint64_t dst_addr) {
        return dst_addr - instr_addr - instr_size;
    }

    static uint64_t MakeJmp(Architecture arch, std::vector<uint8_t>* buf, uint64_t cur_addr, uint64_t jmp_addr) {
        switch (arch) {
        case Architecture::kX86: {
            if (buf->size() < 5) {
                buf->resize(5);
            }
            buf->operator[](0) = 0xe9;        // jmp
            *(uint32_t*)&buf->operator[](1) = GetInstrOffset(cur_addr, 5, jmp_addr);

            for (int i = 5; i < buf->size(); i++) {
                buf->operator[](i) = 0xcc;        // int 3
            }
            break;
        }
        case Architecture::kAmd64: {
            if (buf->size() < 14) buf->resize(14);
            buf->operator[](0) = 0x68;        // push low_addr
            *(uint32_t*)&buf->operator[](1) = (uint64_t)jmp_addr & 0xffffffff;
            buf->operator[](5) = 0xc7;        // mov dword ptr ss:[rsp+4], high_addr
            buf->operator[](6) = 0x44;
            buf->operator[](7) = 0x24;
            buf->operator[](8) = 0x04;
            *(uint32_t*)&buf->operator[](9) = (uint64_t)jmp_addr >> 32;
            buf->operator[](13) = 0xc3;        // ret

            for (int i = 14; i < buf->size(); i++) {
                buf->operator[](i) = 0xcc;        // int 3
            }
            break;
        }
        }
        return buf->size();
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
