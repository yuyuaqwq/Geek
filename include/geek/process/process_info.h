#ifndef GEEK_PROCESS_PROCESS_INFO_H_
#define GEEK_PROCESS_PROCESS_INFO_H_

#include <string>
#include <Windows.h>
#include <tlhelp32.h>

#include <geek/wow64ext/wow64extdefs.h>

namespace geek {
class ProcessInfo
{
public:
    ProcessInfo(const PROCESSENTRY32W& entry) : entry_(entry) {}

    uint32_t ProcessId() const { return entry_.th32ProcessID; }
    uint32_t ParentProcessId() const { return entry_.th32ParentProcessID; }
    std::wstring ExeFile() const { return entry_.szExeFile; }

private:
    PROCESSENTRY32W entry_;
};

} // geek

#endif // GEEK_PROCESS_PROCESS_INFO_H_