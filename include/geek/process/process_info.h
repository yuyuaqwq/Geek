#ifndef GEEK_PROCESS_PROCESS_INFO_H_
#define GEEK_PROCESS_PROCESS_INFO_H_

#include <string>
#include <Windows.h>
#include <tlhelp32.h>

namespace geek {

struct ProcessInfo {
    explicit ProcessInfo(const PROCESSENTRY32W& entry);
    ~ProcessInfo() = default;

    DWORD process_id;
    DWORD parent_process_id;
    std::wstring process_name;
};

} // geek

#endif // GEEK_PROCESS_PROCESS_INFO_H_