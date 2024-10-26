#ifndef GEEK_PROCESS_DEBUG_H_
#define GEEK_PROCESS_DEBUG_H_

#include <format>
#include <string>
#include <functional>
#include <unordered_map>

#include <geek/process/process.hpp>

namespace geek {

class Debug {
public:
    /*
    * 返回值: true表示成功处理调试事件，false表示继续分发该事件
    */
    using CreateProcessEvenet = std::function<bool(CREATE_PROCESS_DEBUG_INFO&)>;
    using CreateThreadEvenet = std::function<bool(CREATE_THREAD_DEBUG_INFO&)>;
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
    Debug(Process& bind_process) noexcept : process_{ bind_process } {
        thread_id_ = 0;
        
        continue_ = false;
        suspend_ = false;
        first_break_point_ = false;
        active_ = false;
    }

    bool Active() {
        active_ = true;
        return DebugActiveProcess(process_.GetId());
    }

    bool Loop() {
        bool success = true;
        continue_ = true;
        while (continue_) {
            DEBUG_EVENT event;
            if (!WaitForDebugEventEx(&event, INFINITE)) {
                continue_ = false;
                success = false;
                break;
            }

            DWORD dbg_status = DBG_EXCEPTION_NOT_HANDLED;

            suspend_ = true;
            thread_id_ = event.dwThreadId;

            switch (event.dwDebugEventCode) {
            case CREATE_PROCESS_DEBUG_EVENT: {
                if (create_process_event_) {
                    if (create_process_event_(event.u.CreateProcessInfo)) {
                        dbg_status = DBG_CONTINUE;
                        break;
                    }
                }
                CloseHandle(event.u.CreateProcessInfo.hFile);
                break;
            }
            case CREATE_THREAD_DEBUG_EVENT: {
                if (create_thread_event_) {
                    if (create_thread_event_(event.u.CreateThread)) {
                        dbg_status = DBG_CONTINUE;
                        break;
                    }
                }
                break;
            }
            case EXCEPTION_DEBUG_EVENT: {
                if (exception_event_) {
                    if (exception_event_(event.u.Exception.ExceptionRecord)) {
                        dbg_status = DBG_CONTINUE;
                        break;
                    }
                }
                switch (event.u.Exception.ExceptionRecord.ExceptionCode) {
                case EXCEPTION_BREAKPOINT: {
                    if (BreakPointHandler(event.u.Exception.ExceptionRecord)) {
                        dbg_status = DBG_CONTINUE;
                        break;
                    }
                    break;
                }
                case EXCEPTION_SINGLE_STEP: {
                    if (SingleStepHandler(event.u.Exception.ExceptionRecord)) {
                        dbg_status = DBG_CONTINUE;
                        break;
                    }
                    break;
                }
                }
                break;
            }
            case EXIT_PROCESS_DEBUG_EVENT: {
                if (exit_process_event_) {
                    if (exit_process_event_(event.u.ExitProcess)) {
                        dbg_status = DBG_CONTINUE;
                        break;
                    }
                }
                ExitLoop();
                break;
            }
            case EXIT_THREAD_DEBUG_EVENT: {
                if (exit_thread_event_) {
                    if (exit_thread_event_(event.u.ExitThread)) {
                        dbg_status = DBG_CONTINUE;
                        break;
                    }
                }
                break;
            }
            case LOAD_DLL_DEBUG_EVENT: {
                if (load_dll_event_) {
                    if (load_dll_event_(event.u.LoadDll)) {
                        dbg_status = DBG_CONTINUE;
                        break;
                    }
                }
                CloseHandle(event.u.LoadDll.hFile);
                break;
            }
            case OUTPUT_DEBUG_STRING_EVENT: {
                if (output_debug_string_event_) {
                    if (output_debug_string_event_(event.u.DebugString)) {
                        dbg_status = DBG_CONTINUE;
                        break;
                    }
                }
                break;
            }
            case RIP_EVENT: {
                if (rip_event_) {
                    if (rip_event_(event.u.RipInfo)) {
                        dbg_status = DBG_CONTINUE;
                        break;
                    }
                }
                break;
            }
            case UNLOAD_DLL_DEBUG_EVENT: {
                if (unload_dll_devent_) {
                    if (unload_dll_devent_(event.u.UnloadDll)) {
                        dbg_status = DBG_CONTINUE;
                        break;
                    }
                }
                break;
            }
            }

            suspend_ = false;
            if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, dbg_status)) {
                continue_ = false;
                success = false;
                break;
            }
        }
        if (active_) {
            Detach();
        }
        return success;
    }

    void ExitLoop() {
        continue_ = false;
    }

    void Detach() {
        DebugActiveProcessStop(process_.GetId());
        active_ = false;
        ExitLoop();
    }

    DWORD GetThreadId() {
        return thread_id_;
    }

    void BindCreateProcessEvent(CreateProcessEvenet event) {
        create_process_event_ = event;
    }

    void BindCreateThreadEvent(CreateThreadEvenet event) {
        create_thread_event_ = event;
    }

    void BindExitProcessEvent(ExitProcessEvent event) {
        exit_process_event_ = event;
    }

    void BindExitThreadEvent(ExitThreadEvent event) {
        exit_thread_event_ = event;
    }

    void BindLoadDllEvent(LoadDllEvent event) {
        load_dll_event_ = event;
    }

    void BindOutputDebugStringEvent(OutputDebugStringEvent event) {
        output_debug_string_event_ = event;
    }

    void BindRipEvent(RipEvent event) {
        rip_event_ = event;
    }

    void BindUnLoadDllEvent(UnLoadDllEvent event) {
        unload_dll_devent_ = event;
    }

    void BindExceptionEvent(ExceptionEvent event) {
        exception_event_ = event;
    }

    /*
    * 系统断点的返回值无效
    */
    void BindSystemBreakPointEvent(BreakPointEvent event) {
        system_break_point_event_ = event;
    }

    bool SetBreakPoint(uint64_t addr, BreakPointEvent event) {
        if (!suspend_) {
            return false;
        }

        if (break_point_map_.find(addr) != break_point_map_.end()) {
            return false;
        }
        uint8_t break_point = 0xcc;
        BreakPointInfo bp_info;
        bp_info.break_point_event = event;
        if (!process_.ReadMemory(addr, &bp_info.old_data, sizeof(bp_info.old_data))) {
            return false;
        }
        if (!process_.WriteMemory(addr, &break_point, sizeof(break_point), true)) {
            return false;
        }
        break_point_map_.insert(std::pair{ addr, std::move(bp_info) });
        return true;
    }

    bool SetSingleStep(DWORD thread_id_, SingleStepEvent event) {
        if (!suspend_) {
            return false;
        }

        auto thread = Thread::Open(thread_id_);
        if (!thread) {
            return false;
        }
        if (process_.IsX86()) {
            _CONTEXT32 context;
            if (!process_.GetThreadContext(&*thread, context)) {
                return false;
            }
            context.EFlags |= 0x100;
            if (!process_.SetThreadContext(&*thread, context)) {
                return false;
            }
        }
        else {
            _CONTEXT64 context;
            if (!process_.GetThreadContext(&*thread, context)) {
                return false;
            }
            context.EFlags |= 0x100;
            if (!process_.SetThreadContext(&*thread, context)) {
                return false;
            }
        }
        SingleStepInfo ss_info;
        ss_info.single_step_event = event;
        single_step_map_.insert(std::pair{ thread_id_, std::move(ss_info) });

        return true;
    }

private:
    bool BreakPointHandler(EXCEPTION_RECORD& record) {
        if (!first_break_point_) {
            first_break_point_ = true;
            if (system_break_point_event_) {
                system_break_point_event_(record);
            }
            return true;
        }

        auto iter = break_point_map_.find(reinterpret_cast<uint64_t>(record.ExceptionAddress));
        if (iter == break_point_map_.end()) {
            return false;
        }
        auto thread = Thread::Open(thread_id_);
        if (!thread) {
            return false;
        }
        
        if (process_.IsX86()) {
            _CONTEXT32 context;
            if (!process_.GetThreadContext(&*thread, context)) {
                return false;
            }
            --context.Eip;
            if (!process_.SetThreadContext(&*thread, context)) {
                return false;
            }
        }
        else {
            _CONTEXT64 context;
            if (!process_.GetThreadContext(&*thread, context)) {
                return false;
            }
            --context.Rip;
            if (!process_.SetThreadContext(&*thread, context)) {
                return false;
            }
        }

        if (!process_.WriteMemory(reinterpret_cast<uint64_t>(record.ExceptionAddress), &iter->second.old_data, sizeof(iter->second.old_data))) {
            return false;
        }

        auto res = iter->second.break_point_event(record);
        
        if (res) {
            return SetSingleStep(thread_id_, [&](EXCEPTION_RECORD& record) -> bool {
                auto addr = iter->first;
                auto event = iter->second.break_point_event;
                break_point_map_.erase(iter);
                SetBreakPoint(addr, event);
                return false;
            });
        }
        else {
            break_point_map_.erase(iter);
        }
        return true;
    }

    bool SingleStepHandler(EXCEPTION_RECORD& record) {
        auto thread = Thread::Open(thread_id_);
        if (!thread) {
            return false;
        }
        if (process_.IsX86()) {
            _CONTEXT32 context;
            if (!process_.GetThreadContext(&*thread, context, CONTEXT_DEBUG_REGISTERS)) {
                return false;
            }
            if (context.Dr6 & 0xf) {
                return DbgRegisterHandler(record);
            }
        }
        else {
            _CONTEXT64 context;
            if (!process_.GetThreadContext(&*thread, context, CONTEXT64_DEBUG_REGISTERS)) {
                return false;
            }
            if (context.Dr6 & 0xf) {
                return DbgRegisterHandler(record);
            }
        }

        auto iter = single_step_map_.find(thread_id_);
        if (iter == single_step_map_.end()) {
            return false;
        }
        
        auto res = iter->second.single_step_event(record);
        if (res) {
            auto thread_id = iter->first;
            auto event = iter->second.single_step_event;
            SetSingleStep(thread_id, event);
        }
        else {
            single_step_map_.erase(iter);
        }
    }

    bool DbgRegisterHandler(EXCEPTION_RECORD& record) {
        return false;
    }

private:
    Process& process_;
    bool active_;
    bool continue_;
    bool suspend_;
    bool first_break_point_;
    DWORD thread_id_;

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


    CreateProcessEvenet create_process_event_;
    CreateThreadEvenet create_thread_event_;
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