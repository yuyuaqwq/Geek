#ifndef GEEK_PROCESS_MODULE_INFO_H_
#define GEEK_PROCESS_MODULE_INFO_H_

#include <optional>
#include <string>

#include <geek/wow64ext/wow64ext.h>

namespace geek {
class Process;
class ModuleListNode;

class ModuleList
{
public:
    ModuleList(Process* proc);

    std::optional<PEB_LDR_DATA32> PebLdrData32() const;
    std::optional<PEB_LDR_DATA64> PebLdrData64() const;

    bool IsX32() const;

    ModuleListNode begin() const;
    ModuleListNode end() const;

private:
    friend class ModuleListNode;
    Process* proc_;
    uint64_t begin_link_;
};

class ModuleListNode
{
public:
    using iterator_category = std::bidirectional_iterator_tag;

    ModuleListNode() = default;
    ModuleListNode(ModuleList* owner, uint64_t entry);

    bool IsX32() const;

    std::optional<LDR_DATA_TABLE_ENTRY32> LdrDataTableEntry32() const;
    std::optional<LDR_DATA_TABLE_ENTRY64> LdrDataTableEntry64() const;

    std::optional<std::wstring> FullDllName() const;
    std::optional<std::wstring> BaseDllName() const;

    ModuleListNode& operator++();
    ModuleListNode operator++(int);

    ModuleListNode& operator--();
    ModuleListNode operator--(int);

    bool operator==(const ModuleListNode& right) const;

private:
    uint64_t entry_ = 0;
    ModuleList* owner_ = nullptr;
};
};

#endif // GEEK_PROCESS_MODULE_INFO_H_