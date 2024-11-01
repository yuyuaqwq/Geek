#include <geek/process/module_list.h>

#include <cassert>

#include "list_entry.h"
#include <geek/process/process.h>

namespace geek {
ModuleList::ModuleList(Process* proc)
	: proc_(proc)
{
	if (proc_->IsX86())
	{
		auto ldr = PebLdrData32();
		if (!ldr) return {};
		begin_link_ = ldr->InLoadOrderModuleList.Flink;
	}
	else
	{
		auto ldr = PebLdrData64();
		if (!ldr) return {};
		begin_link_ = ldr->InLoadOrderModuleList.Flink;
	}
}

std::optional<PEB_LDR_DATA32> ModuleList::PebLdrData32() const
{
	auto peb = proc_->RawPeb32();
	if (!peb)
		return std::nullopt;
	PEB_LDR_DATA32 ldr;
	if (!proc_->ReadMemory(peb->Ldr, &ldr, sizeof(ldr)))
		return std::nullopt;
	return ldr;
}

std::optional<PEB_LDR_DATA64> ModuleList::PebLdrData64() const
{
	auto peb = proc_->RawPeb64();
	if (!peb)
		return std::nullopt;
	PEB_LDR_DATA64 ldr;
	if (!proc_->ReadMemory(peb->Ldr, &ldr, sizeof(ldr)))
		return std::nullopt;
	return ldr;
}

bool ModuleList::IsX32() const
{
	return proc_->IsX86();
}

ModuleListNode ModuleList::begin() const
{
	return { const_cast<ModuleList*>(this), begin_link_ };
}

ModuleListNode ModuleList::end() const
{
	return { const_cast<ModuleList*>(this), 0 };
}

ModuleListNode::ModuleListNode(ModuleList* owner, uint64_t entry)
	: entry_(entry), owner_(owner)
{
}

bool ModuleListNode::IsX32() const
{
	return owner_->IsX32();
}

std::optional<LDR_DATA_TABLE_ENTRY32> ModuleListNode::LdrDataTableEntry32() const
{
	LDR_DATA_TABLE_ENTRY32 entry;
	if (!owner_->proc_->ReadMemory(entry_, &entry, sizeof(entry)))
		return std::nullopt;
	return entry;
}

std::optional<LDR_DATA_TABLE_ENTRY64> ModuleListNode::LdrDataTableEntry64() const
{
	LDR_DATA_TABLE_ENTRY64 entry;
	if (!owner_->proc_->ReadMemory(entry_, &entry, sizeof(entry)))
		return std::nullopt;
	return entry;
}

std::optional<std::wstring> ModuleListNode::FullDllName() const
{
	std::wstring name;
	uint64_t buffer_addr;
	if (IsX32())
	{
		auto ldt = LdrDataTableEntry32();
		if (!ldt) return std::nullopt;
		name.resize(ldt->FullDllName.Length);
		buffer_addr = ldt->FullDllName.Buffer;
	}
	else
	{
		auto ldt = LdrDataTableEntry64();
		if (!ldt) return std::nullopt;
		name.resize(ldt->FullDllName.Length);
		buffer_addr = ldt->FullDllName.Buffer;
	}
	if (!owner_->proc_->ReadMemory(buffer_addr, name.data(), name.size()))
		return std::nullopt;

	return name;
}

std::optional<std::wstring> ModuleListNode::BaseDllName() const
{
	std::wstring name;
	uint64_t buffer_addr;
	if (IsX32())
	{
		auto ldt = LdrDataTableEntry32();
		if (!ldt) return std::nullopt;
		name.resize(ldt->BaseDllName.Length);
		buffer_addr = ldt->BaseDllName.Buffer;
	}
	else
	{
		auto ldt = LdrDataTableEntry64();
		if (!ldt) return std::nullopt;
		name.resize(ldt->BaseDllName.Length);
		buffer_addr = ldt->BaseDllName.Buffer;
	}
	if (!owner_->proc_->ReadMemory(buffer_addr, name.data(), name.size()))
		return std::nullopt;

	return name;
}

ModuleListNode& ModuleListNode::operator++()
{
	ListEntry entry(owner_->proc_, entry_);
	assert(entry.IsValid());
	entry_ = entry.Flink().addr();

	// 如果下一个节点等于开始节点，说明到了末尾
	if (entry_ == owner_->begin_link_)
	{
		// 置0表示末尾
		entry_ = 0;
	}
	return *this;
}

ModuleListNode ModuleListNode::operator++(int)
{
	auto tmp = *this;
	++*this;
	return tmp;
}

ModuleListNode& ModuleListNode::operator--()
{
	ListEntry entry(owner_->proc_, entry_);
	assert(entry.IsValid());
	entry_ = entry.Blink().addr();
	return *this;
}

ModuleListNode ModuleListNode::operator--(int)
{
	auto tmp = *this;
	--*this;
	return tmp;
}

bool ModuleListNode::operator==(const ModuleListNode& right) const
{
	return owner_ == right.owner_ && entry_ == right.entry_;
}
}
