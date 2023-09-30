#ifndef GEEK_PROCESS_MEMORY_INFO_H_
#define GEEK_PROCESS_MEMORY_INFO_H_

#include <string>

#include <Windows.h>

#include <geek/wow64ext/wow64ext.h>

namespace Geek {

struct MemoryInfo {
    explicit MemoryInfo(const MEMORY_BASIC_INFORMATION32& entry) {
        base = entry.BaseAddress;
        size = entry.RegionSize;
        protect = entry.Protect;
        state = entry.State;
    }
    explicit MemoryInfo(const MEMORY_BASIC_INFORMATION64& entry) {
        base = entry.BaseAddress;
        size = entry.RegionSize;
        protect = entry.Protect;
        state = entry.State;
    }

    ~MemoryInfo() {

    }

    uint64_t base;
    uint64_t size;
    uint32_t protect;
    uint32_t state;

};

};

#endif // GEEK_PROCESS_MEMORY_INFO_H_