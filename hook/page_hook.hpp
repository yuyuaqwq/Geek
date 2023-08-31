#ifndef GEEK_HOOK_PAGE_HOOK_H_
#define GEEK_HOOK_PAGE_HOOK_H_

#include <type_traits>
#include <unordered_map>

#include <Windows.h>


namespace Geek {

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


public:
    PageHook() {
        m_status = Status::kNormal;
        m_hook_addr = nullptr;
        m_callback = nullptr;

        if (ms_veh_count == 0) {
            m_exception_handler_handle = AddVectoredExceptionHandler(TRUE, ExceptionHandler);
        }
        ++ms_veh_count;
    }

    ~PageHook() {
        --ms_veh_count;
        if (ms_veh_count == 0) {
            RemoveVectoredExceptionHandler(m_exception_handler_handle);
        }

        Uninstall();
    }


public:
    bool Install(void* hookAddr, HookCallBack callback, DWORD protect = PAGE_READONLY) {
        if (m_status == Status::kNormal) {
            m_status = Status::kRepeatInstall;
            return false;
        }

        auto it_addr = ms_page_hook_addr.find(hookAddr);
        if (it_addr != ms_page_hook_addr.end()) {
            m_status = Status::kDuplicateAddress;
            return false;
        }

        LPVOID page_base = PageAlignment(hookAddr);

        m_hook_addr = hookAddr;
        m_callback = callback;
        m_status = Status::kNormal;

        ms_page_hook_addr.insert(std::pair<void*, PageHook&>(hookAddr, *this));
        auto it_base = ms_page_hook_base.find(page_base);
        if (it_base == ms_page_hook_base.end()) {
            PageRecord pageRecord;
            pageRecord.count = 1;
            pageRecord.page_base = page_base;
            pageRecord.protect = 0;
            ms_page_hook_base.insert(std::pair<void*, PageRecord>(page_base, pageRecord));
            it_base = ms_page_hook_base.find(page_base);
            if (!VirtualProtect(page_base, 0x1000, protect, &it_base->second.protect)) {
                Uninstall();
                m_status = Status::kSetProtectFailed;
                return false;
            }
        }
        else {
            ++it_base->second.count;
        }
        return true;
    }

    bool Uninstall() noexcept {
        if (m_status != Status::kNormal) {
            return true;
        }

        LPVOID page_base = PageAlignment(m_hook_addr);
        auto it_base = ms_page_hook_base.find(page_base);

        if (it_base != ms_page_hook_base.end()) {
            if (it_base->second.count == 1) {
                if (!VirtualProtect(page_base, 0x1000, it_base->second.protect, &it_base->second.protect)) {
                    m_status = Status::kSetProtectFailed;
                    return false;
                }
                ms_page_hook_base.erase(it_base);
            }
            else {
                --it_base->second.count;
            }
        }

        ms_page_hook_addr.erase(m_hook_addr);

        m_hook_addr = nullptr;
        m_callback = nullptr;

        m_status = Status::kUnhooked;
        return true;
    }


private:

    struct PageRecord {
        LPVOID page_base;
        size_t count;
        DWORD protect;
    };

private:
    static LPVOID PageAlignment(LPVOID addr) noexcept {
        return (LPVOID)((UINT_PTR)addr & (UINT_PTR)(~0xfff));
    }

    static LONG NTAPI ExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo) {
        if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {

            LPVOID address = (LPVOID)ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
            LPVOID page_base = PageAlignment(address);
            auto it_base = ms_page_hook_base.find(page_base);
            if (it_base == ms_page_hook_base.end()) {
                return EXCEPTION_CONTINUE_SEARCH;
            }

            VirtualProtect(page_base, 0x1000, it_base->second.protect, &it_base->second.protect);

            LPCONTEXT context = ExceptionInfo->ContextRecord;

            auto it_addr = ms_page_hook_addr.find(address);
            if (it_addr != ms_page_hook_addr.end()) {
                it_addr->second.mCallback(context);
            }

            // 设置TF，单步后再次设置页面属性
            context->EFlags |= 0x100;

            ms_page_hook_step.insert(std::pair<DWORD, PageRecord&>(GetCurrentThreadId(), it_base->second));

            return EXCEPTION_CONTINUE_EXECUTION;

        }
        else if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
        {
            LPCONTEXT context = ExceptionInfo->ContextRecord;
            if (context->Dr6 & 0xf) {
                return EXCEPTION_CONTINUE_SEARCH;
            }
            else {
                auto it = ms_page_hook_step.find(GetCurrentThreadId());
                if (it == ms_page_hook_step.end()) {
                    return EXCEPTION_CONTINUE_SEARCH;
                }

                // �ָ�Hook
                DWORD uselessProtect;
                VirtualProtect(it->second.page_base, 0x1000, it->second.protect, &it->second.protect);

                ms_page_hook_step.erase(GetCurrentThreadId());

                // 不需要设置TF
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

private:
    Status m_status;
    void* m_exception_handler_handle;
    void* m_hook_addr;
    HookCallBack m_callback;

    // C++17
    inline static int ms_veh_count = 0;
    inline static std::unordered_map<void*, PageRecord> ms_page_hook_base;
    inline static std::unordered_map<void*, PageHook&> ms_page_hook_addr;
    inline static std::unordered_map<DWORD, PageRecord&> ms_page_hook_step;
};

} // namespace PageHook

#endif // GEEK_HOOK_PAGE_HOOK_H_
