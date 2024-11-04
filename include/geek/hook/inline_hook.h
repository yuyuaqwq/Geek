#ifndef GEEK_HOOK_INLINE_HOOK_H_
#define GEEK_HOOK_INLINE_HOOK_H_

#include <Windows.h>

#include <vector>
#include <geek/process/process.h>


namespace geek {
enum class Architecture {
    kCurrentRunning,
    kX32,
    kAmd64,
};

class InlineHook {
public:
    struct HookContextX32 {
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

        uint32_t proc_id;
    };
    struct HookContextAmd64 {
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

        uint32_t proc_id;
    };

    using HookCallbackX32 = bool(__fastcall*)(HookContextX32* ctx);
    using HookCallbackAmd64 = bool(*)(HookContextAmd64* ctx);

    ~InlineHook() = default;
    
    /**
     * ��װͨ��ת������Hook
     * ����������λ��hook������ΪHookContext*�����������������ܹ�����
     * ֧���ڻص������е���ԭ����
     *
     * ʵ�ֽӹܣ�
     * �ں�����ʼhook
     * pop_stack_top = true
     * callback�� context->esp += 4 / context->rsp += 8;	// �����ⲿcall���ú����ķ��ص�ַ
     * ע��x32�»���Ҫ���ݵ���Լ����ȷ���Ƿ���Ҫ������ϲ��������ֽڣ�����stdcall����Ҫ + count * 4����cdecl����Ҫ
     * callback��ָ�� context->jmp_addr = context->stack[0];      // ֱ�ӷ��ص����ñ�hook�����ĵ��ô�
     * callback�з���false      // ��ִ��ԭָ��
     *
     * ʵ�ּ��ӣ�
     * ��ӹܻ���һ��
     * ��Ҫ��ȡԭ����ִ�н��
     *      ֱ����callback���ٴε���ԭ�����Ի�ȡ�����н��
     *      ����false        // ��ִ��ԭָ��
     * ����Ҫ��ȡԭ����ִ�н��
     *      ���޸�esp/rsp�Լ�jmp_addr
     *      ����true
     *      ִ��ԭָ���п��ܻ����(ԭָ���д������ƫ��ָ��)���������ԭʼ�������޸�sp��jmp_addr�ٷ���false
     *
     * ԭ��
     * ����Tls�洢������Ϣ����������ִ��ԭָ�����ȥ����ִ��
     *
     * ע�⣺
     * 1. ����Hook TlsGetValue��TlsSetValue
     * 2. ��hook�����ڸ�д��ָ��ܴ������ƫ��ָ��
     * 3. �����Ҫ����̽����������ɵĺ���������Ŀ����̣���ر�/GS(��ȫ���)����������__security_cookie�������
     * 4. �����Ҫ�޸�rsp����jmp_addr��ע���ջƽ��
     *      Ĭ�������jmp_addr��ָ��hook������һ��ָ��
     *      push��pop˳��Ϊ    push esp -> push jmp_addr -> push xxx    call    pop xxx -> pop&save jmp_addr -> pop esp -> �Ƿ�ִ��ԭָ�� -> get&push jmp_addr -> ret
     * 5. Amd64�¹���ջ֡ʱӦ������16�ֽڶ���ģ����򲿷�ָ��(�����)���ܻ��쳣
     *
     * @param hook_addr Ҫhook�ĵ�ַ
     * @param callback �ص��ĺ���ָ��
     * @param instr_size x32Ҫ��instr_size>=5��x64Ҫ��instr_size>=14����instr_size���ܴ���255
     * @param save_volatile_register 
     * @param arch 
     * @param forward_page_size ת��ҳ�棬������Ҫ0x1000��ǰ0x1000���ɸ�д������ָ���϶�Ŀռ䣬���ڽ�������
     * @return 
     */
    static bool InstallEx(
        const Process* proc,
        uint64_t hook_addr,
        uint64_t callback,
        size_t instr_size = 0,
        bool save_volatile_register = true,
        Architecture arch = Architecture::kCurrentRunning,
        uint64_t forward_page_size = 0x1000
    );
    static bool InstallX32Ex(
        const Process* proc,
        uint32_t hook_addr,
        HookCallbackX32 callback,
        size_t instr_size = 0,
        bool save_volatile_register = true,
        uint64_t forward_page_size = 0x1000);

    static bool InstallAmd64Ex(
        const Process* proc,
        uint64_t hook_addr,
        HookCallbackAmd64 callback,
        size_t instr_size = 0,
        bool save_volatile_register = true,
        uint64_t forward_page_size = 0x1000);

    static bool InstallX32(
        const Process* proc,
        uint32_t hook_addr,
        std::function<bool(HookContextX32* ctx)>&& callback,
        size_t instr_size = 0,
        bool save_volatile_register = true,
        uint64_t forward_page_size = 0x1000);

    static bool InstallAmd64(
        const Process* proc,
        uint64_t hook_addr,
        std::function<bool(HookContextAmd64* ctx)>&& callback,
        size_t instr_size = 0,
        bool save_volatile_register = true,
        uint64_t forward_page_size = 0x1000);

    static bool InstallX32(
        uint32_t hook_addr,
        std::function<bool(HookContextX32* ctx)>&& callback,
        size_t instr_size = 0,
        bool save_volatile_register = true,
        uint64_t forward_page_size = 0x1000);

    static bool InstallAmd64(
        uint64_t hook_addr,
        std::function<bool(HookContextAmd64* ctx)>&& callback,
        size_t instr_size = 0,
        bool save_volatile_register = true,
        uint64_t forward_page_size = 0x1000);

    /**
    * ж��Hook
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
