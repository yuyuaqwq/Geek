#ifndef GEEK_PROCESS_MEMORY_INFO_H_
#define GEEK_PROCESS_MEMORY_INFO_H_

#include <string>

#include <geek/wow64ext/wow64ext.h>

namespace geek {

struct MemoryInfo {
    explicit MemoryInfo(const MEMORY_BASIC_INFORMATION32& entry);
    explicit MemoryInfo(const MEMORY_BASIC_INFORMATION64& entry);
    ~MemoryInfo() = default;

    uint64_t base;
    uint64_t size;
    uint32_t protect;
    uint32_t state;

};

};

#endif // GEEK_PROCESS_MEMORY_INFO_H_