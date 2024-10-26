#ifndef GEEK_PROCESS_PROCESS_INFO_H_
#define GEEK_PROCESS_PROCESS_INFO_H_

#include <string>

#include <Windows.h>

#include <geek/wow64ext/wow64ext.h>

namespace geek {

struct ProcessInfo {
    explicit ProcessInfo(const PROCESSENTRY32W& entry) {
        process_id = entry.th32ProcessID;
        parent_process_id = entry.th32ParentProcessID;
        process_name = entry.szExeFile;
    }

    ~ProcessInfo() {

    }

    uint64_t process_id;
    uint64_t parent_process_id;
    std::wstring process_name;
};

} // geek

#endif // GEEK_PROCESS_PROCESS_INFO_H_