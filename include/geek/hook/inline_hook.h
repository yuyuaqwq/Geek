#ifndef GEEK_HOOK_INLINE_HOOK_H_
#define GEEK_HOOK_INLINE_HOOK_H_

#include <Windows.h>

#include <vector>
#include <geek/process/process.h>
#include <geek/global.h>


namespace geek {
class InlineHook {
public:
    struct HookContextX86 {
        uint32_t* const stack;
        uint32_t esp;
        uint32_t jmp_addr;
        uint32_t forward_page_base;
        uint32_t hook_addr;
        uint32_t reserve[11];

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
    struct HookContextX64 {
        uint64_t* const stack;
        uint64_t rsp;
        uint64_t jmp_addr;
        uint64_t forward_page_base;
        uint64_t hook_addr;
        uint64_t reserve[11];

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

    using HookCallbackX86 = bool(__fastcall*)(HookContextX86* ctx);
    using HookCallbackX64 = bool(*)(HookContextX64* ctx);

    ~InlineHook() = default;
    
    /**
     * 安装通用转发调用Hook
     * 可以在任意位置hook，参数为HookContext*，具体类型因处理器架构而异
     * 支持在回调函数中调用原函数
     *
     * 实现接管：
     * 在函数起始hook
     * pop_stack_top = true
     * callback中 context->esp += 4 / context->rsp += 8;	// 跳过外部call到该函数的返回地址
     * 注：x32下还需要根据调用约定来确定是否需要额外加上参数数量字节，比如stdcall就需要 + count * 4，但cdecl不需要
     * callback中指定 context->jmp_addr = context->stack[0];      // 直接返回到调用被hook函数的调用处
     * callback中返回false      // 不执行原指令
     *
     * 实现监视：
     * 与接管基本一致
     * 需要获取原函数执行结果
     *      直接在callback中再次调用原函数以获取其运行结果
     *      返回false        // 不执行原指令
     * 不需要获取原函数执行结果
     *      不修改esp/rsp以及jmp_addr
     *      返回true
     *      执行原指令有可能会出错(原指令中存在相对偏移指令)，建议调用原始函数后，修改sp和jmp_addr再返回false
     *
     * 原理：
     * 基于Tls存储重入信息，是重入则执行原指令并跳回去继续执行
     *
     * 注意：
     * 1. 不能Hook TlsGetValue，TlsSetValue
     * 2. 被hook处用于覆写的指令不能存在相对偏移指令
     * 3. 如果需要跨进程将编译器生成的函数拷贝到目标进程，请关闭/GS(安全检查)，避免生成__security_cookie插入代码
     * 4. 如果需要修改rsp或者jmp_addr，注意堆栈平衡
     *      默认情况下jmp_addr是指向被hook处的下一行指令
     *      push和pop顺序为    push esp -> push jmp_addr -> push xxx    call    pop xxx -> pop&save jmp_addr -> pop esp -> 是否执行原指令 -> get&push jmp_addr -> ret
     * 5. X64下构建栈帧时应该是以16字节对齐的，否则部分指令(浮点等)可能会异常
     *
     * @param hook_addr 要hook的地址
     * @param callback 回调的函数指针
     * @param instr_size x32要求instr_size>=5，x64要求instr_size>=14，且instr_size不能大于255
     * @param save_volatile_register 
     * @param arch 
     * @param forward_page_size 转发页面，至少需要0x1000，前0x1000不可覆写，可以指定较多的空间，便于交互数据
     * @return 
     */
    static std::optional<InlineHook> InstallEx(
        const Process* proc,
        uint64_t hook_addr,
        uint64_t callback,
        Arch arch,
        size_t instr_size = 0,
        bool save_volatile_register = true,
        uint64_t forward_page_size = 0x1000
    );
    static std::optional<InlineHook> InstallX86Ex(
        const Process* proc,
        uint32_t hook_addr,
        HookCallbackX86 callback,
        size_t instr_size = 0,
        bool save_volatile_register = true,
        uint64_t forward_page_size = 0x1000);

    static std::optional<InlineHook> InstallX64Ex(
        const Process* proc,
        uint64_t hook_addr,
        HookCallbackX64 callback,
        size_t instr_size = 0,
        bool save_volatile_register = true,
        uint64_t forward_page_size = 0x1000);

    static std::optional<InlineHook> InstallX86(
        const Process* proc,
        uint32_t hook_addr,
        std::function<bool(HookContextX86* ctx)>&& callback,
        size_t instr_size = 0,
        bool save_volatile_register = true,
        uint64_t forward_page_size = 0x1000);

    static std::optional<InlineHook> InstallX64(
        const Process* proc,
        uint64_t hook_addr,
        std::function<bool(HookContextX64* ctx)>&& callback,
        size_t instr_size = 0,
        bool save_volatile_register = true,
        uint64_t forward_page_size = 0x1000);

    static std::optional<InlineHook> InstallX86(
        uint32_t hook_addr,
        std::function<bool(HookContextX86* ctx)>&& callback,
        size_t instr_size = 0,
        bool save_volatile_register = true,
        uint64_t forward_page_size = 0x1000);

    static std::optional<InlineHook> InstallX64(
        uint64_t hook_addr,
        std::function<bool(HookContextX64* ctx)>&& callback,
        size_t instr_size = 0,
        bool save_volatile_register = true,
        uint64_t forward_page_size = 0x1000);

    /**
    * 卸载Hook
    */
    void Uninstall();

    uint64_t forward_page() const { return forward_page_; }
    const Process* process() const { return process_; }

private:
    explicit InlineHook(const Process* process);

    const Process* process_;
    uint64_t hook_addr_ = 0;
    uint64_t forward_page_ = 0;
    std::vector<char> old_instr_;
    uint32_t tls_id_ = TLS_OUT_OF_INDEXES;
};

} // namespace geek

#endif // GEEK_HOOK_INLINE_HOOK_H_
