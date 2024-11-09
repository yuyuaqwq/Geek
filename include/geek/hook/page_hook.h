#pragma once
#include <type_traits>
#include <unordered_map>

#include <Windows.h>


namespace geek {

// 基于VEH接管页面异常的hook框架
// 注意hook回调/PageHook代码不能与被hook地址处于同一页面

class PageHook {
public:
    typedef void (*HookCallBack)(LPCONTEXT context);

public:
    enum class Status {
        kNormal = 0,
        kUnhooked,
        kDuplicateAddress,
        kSetProtectFailed,
        kRepeatInstall,
        kRepeatUninstall,
    };

    PageHook();
    ~PageHook();

    bool Install(void* hookAddr, HookCallBack callback, DWORD protect = PAGE_READONLY);

    bool Uninstall() noexcept;

private:

    struct PageRecord {
        LPVOID page_base;
        size_t count;
        DWORD protect;
    };
    static LPVOID PageAlignment(LPVOID addr) noexcept;
    static LONG NTAPI ExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo);

    Status m_status = Status::kNormal;
    void* m_exception_handler_handle = nullptr;
    void* m_hook_addr = nullptr;
    HookCallBack m_callback = nullptr;

    // C++17
    inline static int ms_veh_count = 0;
    inline static std::unordered_map<void*, PageRecord> ms_page_hook_base;
    inline static std::unordered_map<void*, PageHook&> ms_page_hook_addr;
    inline static std::unordered_map<DWORD, PageRecord&> ms_page_hook_step;
};

} // namespace PageHook
