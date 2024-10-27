#ifndef GEEK_PROCESS_DEBUG_H_
#define GEEK_PROCESS_DEBUG_H_

#include <functional>
#include <unordered_map>

#include <geek/process/process.h>

namespace geek {

class Debug {
public:
    /*
    * 返回值: true表示成功处理调试事件，false表示继续分发该事件
    */
    using CreateProcessEvent = std::function<bool(CREATE_PROCESS_DEBUG_INFO&)>;
    using CreateThreadEvent = std::function<bool(CREATE_THREAD_DEBUG_INFO&)>;
    using ExitProcessEvent = std::function<bool(EXIT_PROCESS_DEBUG_INFO&)>;
    using ExitThreadEvent = std::function<bool(EXIT_THREAD_DEBUG_INFO&)>;
    using LoadDllEvent = std::function<bool(LOAD_DLL_DEBUG_INFO&)>;
    using OutputDebugStringEvent = std::function<bool(OUTPUT_DEBUG_STRING_INFO&)>;
    using RipEvent = std::function<bool(RIP_INFO&)>;
    using UnLoadDllEvent = std::function<bool(UNLOAD_DLL_DEBUG_INFO&)>;
    using ExceptionEvent = std::function<bool(EXCEPTION_RECORD&)>;

    /*
    * 返回值: true表示再次设置int 3，false表示不再设置int 3
    */
    using BreakPointEvent = std::function<bool(EXCEPTION_RECORD&)>;
    /*
    * 返回值: true表示再次设置单步，false表示不再设置单步
    */
    using SingleStepEvent = std::function<bool(EXCEPTION_RECORD&)>;

public:
    Debug(Process& bind_process) noexcept;

    bool Active();
    bool Loop();
    void ExitLoop();
    void Detach();
    DWORD thread_id() const { return thread_id_; }

    void BindCreateProcessEvent(const CreateProcessEvent& event) {
        create_process_event_ = event;
    }
    void BindCreateThreadEvent(const CreateThreadEvent& event) {
        create_thread_event_ = event;
    }
    void BindExitProcessEvent(const ExitProcessEvent& event) {
        exit_process_event_ = event;
    }
    void BindExitThreadEvent(const ExitThreadEvent& event) {
        exit_thread_event_ = event;
    }
    void BindLoadDllEvent(const LoadDllEvent& event) {
        load_dll_event_ = event;
    }
    void BindOutputDebugStringEvent(const OutputDebugStringEvent& event) {
        output_debug_string_event_ = event;
    }
    void BindRipEvent(const RipEvent& event) {
        rip_event_ = event;
    }
    void BindUnLoadDllEvent(const UnLoadDllEvent& event) {
        unload_dll_devent_ = event;
    }
    void BindExceptionEvent(const ExceptionEvent& event) {
        exception_event_ = event;
    }
    /*
    * 系统断点的返回值无效
    */
    void BindSystemBreakPointEvent(const BreakPointEvent& event) {
        system_break_point_event_ = event;
    }
    bool SetBreakPoint(uint64_t addr, const BreakPointEvent& event);
    bool SetSingleStep(DWORD thread_id_, const SingleStepEvent& event);

private:
    bool BreakPointHandler(EXCEPTION_RECORD& record);

    bool SingleStepHandler(EXCEPTION_RECORD& record);

    bool DbgRegisterHandler(EXCEPTION_RECORD& record) {
        return false;
    }

private:
    Process& process_;
    bool active_ = false;
    bool continue_ = false;
    bool suspend_ = false;
    bool first_break_point_ = false;
    DWORD thread_id_ = 0;

    struct BreakPointInfo{
        uint8_t old_data;
        BreakPointEvent break_point_event;
    };
    std::unordered_map<uint64_t, BreakPointInfo> break_point_map_;
    struct SingleStepInfo {
        BreakPointEvent single_step_event;
    };
    std::unordered_map<DWORD, SingleStepInfo> single_step_map_;

    BreakPointEvent system_break_point_event_;
    CreateProcessEvent create_process_event_;
    CreateThreadEvent create_thread_event_;
    ExitProcessEvent exit_process_event_;
    ExitThreadEvent exit_thread_event_;
    LoadDllEvent load_dll_event_;
    OutputDebugStringEvent output_debug_string_event_;
    RipEvent rip_event_;
    UnLoadDllEvent unload_dll_devent_;
    ExceptionEvent exception_event_;
};

} // geek

#endif // GEEK_PROCESS_PROCESS_INFO_H_