#ifndef GEEK_SYNC_EVENT_H_
#define GEEK_SYNC_EVENT_H_

#include <Windows.h>

#include <Geek/handle.hpp>

namespace Geek {
namespace sync {

class Event {
public:
    bool Create(const wchar_t* name, bool manual_reset = false, bool init_state = true, bool exists_false = true) {
        UniqueHandle temp = CreateEventW(NULL, manual_reset, init_state, name);
        if (exists_false && GetLastError() == ERROR_ALREADY_EXISTS) {
            return false;
        }
        event_ = std::move(temp);
        return event_.IsValid();
    }

    bool Open(const wchar_t* name) {
        event_.Reset(OpenEventW(SYNCHRONIZE, FALSE, name));
        return event_.IsValid();
    }

    void Close() {
        event_.Reset();
    }

    bool Wait(uint64_t timeout_ms = INFINITE) {
        return WaitForSingleObject(event_.Get(), timeout_ms) == 0;
    }

    bool Set() {
        SetEvent(event_.Get());
    }

    bool Reset() {
        ResetEvent(event_.Get());
    }

private:
    UniqueHandle event_;
};

}
}

#endif // GEEK_SYNC_EVENT_H_