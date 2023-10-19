#ifndef GEEK_PROCESS_DEBUG_H_
#define GEEK_PROCESS_DEBUG_H_

#include <string>
#include <functional>

#include <Geek/process/process.hpp>

namespace Geek {

class Debug {
public:
    using CreateProcessEvenet = std::function<void(CREATE_PROCESS_DEBUG_INFO&)>;
    using CreateThreadEvenet = std::function<void(CREATE_THREAD_DEBUG_INFO&)>;
    using ExitProcessEvent = std::function<void(EXIT_PROCESS_DEBUG_INFO&)>;
    using ExitThreadEvent = std::function<void(EXIT_THREAD_DEBUG_INFO&)>;
    using LoadDllEvent = std::function<void(LOAD_DLL_DEBUG_INFO&)>;
    using OutputDebugStringEvent = std::function<void(OUTPUT_DEBUG_STRING_INFO&)>;
    using RipEvent = std::function<void(RIP_INFO&)>;
    using UnLoadDllEvent = std::function<void(UNLOAD_DLL_DEBUG_INFO&)>;

    using ExceptionBreakPointEvent = std::function<void(EXCEPTION_RECORD&)>;

public:
    Debug(Process& bind_process) : process_{ bind_process } {
        continue_ = true;
    }

    void Loop() {
        while (continue_) {
            DEBUG_EVENT event;
            if (!WaitForDebugEventEx(&event, 1)) {
                break;
            }

            switch (event.dwDebugEventCode) {
            case CREATE_PROCESS_DEBUG_EVENT: {
                if (create_process_event_) {
                    create_process_event_(event.u.CreateProcessInfo);
                }
                break;
            }
            case CREATE_THREAD_DEBUG_EVENT: {
                if (create_thread_event_) {
                    create_thread_event_(event.u.CreateThread);
                }
                break;
            }
            case EXCEPTION_DEBUG_EVENT: {
                switch (event.u.Exception.ExceptionRecord.ExceptionCode) {
                case EXCEPTION_BREAKPOINT:
                    if (exception_break_point_event_) {
                        exception_break_point_event_(event.u.Exception.ExceptionRecord);
                    }
                    break;
                }
                break;
            }
            case EXIT_PROCESS_DEBUG_EVENT: {
                if (exit_process_event_) {
                    exit_process_event_(event.u.ExitProcess);
                }
                break;
            }
            case EXIT_THREAD_DEBUG_EVENT: {
                if (exit_thread_event_) {
                    exit_thread_event_(event.u.ExitThread);
                }
                break;
            }
            case LOAD_DLL_DEBUG_EVENT: {
                if (load_dll_event_) {
                    load_dll_event_(event.u.LoadDll);
                }
                break;
            }
            case OUTPUT_DEBUG_STRING_EVENT: {
                if (output_debug_string_event_) {
                    output_debug_string_event_(event.u.DebugString);
                }
                break;
            }
            case RIP_EVENT: {
                if (rip_event_) {
                    rip_event_(event.u.RipInfo);
                }
                break;
            }
            case UNLOAD_DLL_DEBUG_EVENT: {
                if (unload_dll_devent_) {
                    unload_dll_devent_(event.u.UnloadDll);
                }
                break;
            }
            }
        }
    }

    void ExitLoop() {
        continue_ = false;
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


    void BindExceptionBreakPointEvent(ExceptionBreakPointEvent event) {
        exception_break_point_event_ = event;
    }

    void BindExceptionAccessViolationEvent() {

    }

    void BindExceptionSingleStepEvent() {

    }

private:
    Process& process_;
    bool continue_;

    CreateProcessEvenet create_process_event_;
    CreateThreadEvenet create_thread_event_;
    ExitProcessEvent exit_process_event_;
    ExitThreadEvent exit_thread_event_;
    LoadDllEvent load_dll_event_;
    OutputDebugStringEvent output_debug_string_event_;
    RipEvent rip_event_;
    UnLoadDllEvent unload_dll_devent_;


    ExceptionBreakPointEvent exception_break_point_event_;

};

} // Geek

#endif // GEEK_PROCESS_PROCESS_INFO_H_