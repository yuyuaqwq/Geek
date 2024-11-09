#pragma once
#include <optional>
#include <string>

#include <geek/wow64ext/wow64ext.h>

namespace geek {
class Process;
class ModuleList;

class ModuleListNode
{
public:
    using iterator_category = std::forward_iterator_tag;

    ModuleListNode() = default;
    ModuleListNode(ModuleList* owner, uint64_t entry);

    bool IsX32() const;
    bool IsEnd() const;
    bool IsValid() const;

    std::optional<LDR_DATA_TABLE_ENTRY32> LdrDataTableEntry32() const;
    std::optional<LDR_DATA_TABLE_ENTRY64> LdrDataTableEntry64() const;

    uint32_t SizeOfImage() const;
    uint64_t DllBase() const;
    std::wstring FullDllName() const;
    std::wstring BaseDllName() const;

    ModuleListNode& operator++();
    ModuleListNode operator++(int);

    ModuleListNode& operator*() { return *this; }
    ModuleListNode& operator->() { return *this; }

    bool operator==(const ModuleListNode& right) const;
    bool operator!=(const ModuleListNode& right) const;

    std::wstring DebugName() const;

private:
    uint64_t entry_ = 0;
    ModuleList* owner_ = nullptr;
    mutable std::optional<LDR_DATA_TABLE_ENTRY32> ldte32_;
    mutable std::optional<LDR_DATA_TABLE_ENTRY64> ldte64_;
};

class ModuleList
{
public:
    ModuleList(Process* proc);

    std::optional<PEB_LDR_DATA32> PebLdrData32() const;
    std::optional<PEB_LDR_DATA64> PebLdrData64() const;

    uint64_t AddressOfFirstLink() const;
    uint64_t AddressOfLastLink() const;

    bool IsX32() const;
    bool IsValid() const;

    ModuleListNode begin() const;
    ModuleListNode end() const;

    ModuleListNode FindByModuleBase(uint64_t base) const;
    ModuleListNode FindByModuleName(std::wstring_view name) const;

private:
    friend class ModuleListNode;
    Process* proc_;
    mutable std::optional<PEB_LDR_DATA32> ldr32_;
    mutable std::optional<PEB_LDR_DATA64> ldr64_;
};
};