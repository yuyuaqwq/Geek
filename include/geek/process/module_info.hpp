#ifndef GEEK_PROCESS_MODULE_INFO_H_
#define GEEK_PROCESS_MODULE_INFO_H_

#include <string>

#include <Windows.h>

#include <geek/wow64ext/wow64ext.h>

namespace geek {

struct ModuleInfo {

    ModuleInfo(uint64_t base_, uint32_t size_) {
        base = base_;
        size = size_;
        entry_point = 0;
    }

    ModuleInfo(const LDR_DATA_TABLE_ENTRY64& entry, const std::wstring& base_name_, const std::wstring& full_name_) {
        base = entry.DllBase;
        size = entry.SizeOfImage;
        base_name = base_name_;
        full_name = full_name_;
        entry_point = entry.EntryPoint;
    }
    ModuleInfo(const LDR_DATA_TABLE_ENTRY32& entry, const std::wstring& base_name_, const std::wstring& full_name_) {
        base = entry.DllBase;
        size = entry.SizeOfImage;
        base_name = base_name_;
        full_name = full_name_;
        entry_point = entry.EntryPoint;
    }

    ~ModuleInfo() {

    }

    uint64_t entry_point;
    uint64_t base;
    uint32_t size;
    std::wstring base_name;
    std::wstring full_name;
};

};

#endif // GEEK_PROCESS_MODULE_INFO_H_