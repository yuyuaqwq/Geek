#include <geek/process/module_list.h>

#include <cassert>

#include "list_entry.h"
#include <geek/process/process.h>
#include <geek/utils/converter.h>

namespace geek {
ModuleList::ModuleList(Process* proc)
	: proc_(proc)
{
	if (proc_->IsX86())
	{
		auto ldr = PebLdrData32();
		if (!ldr) return;
		begin_link_ = ldr->InLoadOrderModuleList.Flink;
	}
	else
	{
		auto ldr = PebLdrData64();
		if (!ldr) return;
		begin_link_ = ldr->InLoadOrderModuleList.Flink;
	}
}

std::optional<PEB_LDR_DATA32> ModuleList::PebLdrData32() const
{
	if (!ldr32_)
	{
		auto peb = proc_->Peb32();
		if (!peb)
			return std::nullopt;
		PEB_LDR_DATA32 ldr;
		if (!proc_->ReadMemory(peb->Ldr, &ldr, sizeof(ldr)))
			return std::nullopt;
		ldr32_ = ldr;
	}
	return ldr32_;
}

std::optional<PEB_LDR_DATA64> ModuleList::PebLdrData64() const
{
	if (!ldr64_)
	{
		auto peb = proc_->Peb64();
		if (!peb)
			return std::nullopt;
		PEB_LDR_DATA64 ldr;
		if (!proc_->ReadMemory(peb->Ldr, &ldr, sizeof(ldr)))
			return std::nullopt;
		ldr64_ = ldr;
	}
	return ldr64_;
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

ModuleListNode ModuleList::FindByModuleBase(uint64_t base) const
{
	for (auto& m : *this)
	{
		if (m.DllBase() == base)
			return m;
	}
	return end();
}

ModuleListNode ModuleList::FindByModuleName(std::wstring_view name) const
{
	auto n = Convert::ToUppercase(name);

	for (auto& m : *this)
	{
		auto n2 = Convert::ToUppercase(m.BaseDllName());
		if (n2 == n)
			return m;
	}
	return end();
}

ModuleListNode::ModuleListNode(ModuleList* owner, uint64_t entry)
	: entry_(entry), owner_(owner)
{
}

bool ModuleListNode::IsX32() const
{
	return owner_->IsX32();
}

bool ModuleListNode::IsEnd() const
{
	return owner_ == nullptr || entry_ == 0;
}

bool ModuleListNode::IsValid() const
{
	if (IsEnd())
		return false;
	if (IsX32())
	{
		return LdrDataTableEntry32().has_value();
	}
	else
	{
		return LdrDataTableEntry64().has_value();
	}
}

std::optional<LDR_DATA_TABLE_ENTRY32> ModuleListNode::LdrDataTableEntry32() const
{
	if (!ldte32_) {
		LDR_DATA_TABLE_ENTRY32 entry;
		if (!owner_->proc_->ReadMemory(entry_, &entry, sizeof(entry)))
			return std::nullopt;
		ldte32_ = entry;
	}
	return ldte32_;
}

std::optional<LDR_DATA_TABLE_ENTRY64> ModuleListNode::LdrDataTableEntry64() const
{
	if (!ldte64_)
	{
		LDR_DATA_TABLE_ENTRY64 entry;
		if (!owner_->proc_->ReadMemory(entry_, &entry, sizeof(entry)))
			return std::nullopt;
		ldte64_ = entry;
	}
	return ldte64_;
}

uint32_t ModuleListNode::SizeOfImage() const
{
	assert(IsValid());
	if (IsX32())
	{
		auto ldt = LdrDataTableEntry32();
		return ldt->SizeOfImage;
	}
	else
	{
		auto ldt = LdrDataTableEntry64();
		return ldt->SizeOfImage;
	}
}

uint64_t ModuleListNode::DllBase() const
{
	assert(IsValid());
	if (IsX32())
	{
		auto ldt = LdrDataTableEntry32();
		return ldt->DllBase;
	}
	else
	{
		auto ldt = LdrDataTableEntry64();
		return ldt->DllBase;
	}
}

std::wstring ModuleListNode::FullDllName() const
{
	assert(IsValid());
	std::vector<wchar_t> name;
	uint64_t buffer_addr;
	if (IsX32())
	{
		auto ldt = LdrDataTableEntry32();
		name.resize(ldt->FullDllName.Length + 1);
		buffer_addr = ldt->FullDllName.Buffer;
	}
	else
	{
		auto ldt = LdrDataTableEntry64();
		name.resize(ldt->FullDllName.Length + 1);
		buffer_addr = ldt->FullDllName.Buffer;
	}
	if (!owner_->proc_->ReadMemory(buffer_addr, name.data(), name.size()))
		throw std::exception("Is failure possible here? See geek::LastError for more information!");

	return name.data();
}

std::wstring ModuleListNode::BaseDllName() const
{
	assert(IsValid());
	std::vector<wchar_t> name;
	uint64_t buffer_addr;
	if (IsX32())
	{
		auto ldt = LdrDataTableEntry32();
		name.resize(ldt->BaseDllName.Length + 1);
		buffer_addr = ldt->BaseDllName.Buffer;
	}
	else
	{
		auto ldt = LdrDataTableEntry64();
		name.resize(ldt->BaseDllName.Length + 1);
		buffer_addr = ldt->BaseDllName.Buffer;
	}
	if (!owner_->proc_->ReadMemory(buffer_addr, name.data(), name.size()))
		throw std::exception("Is failure possible here? See geek::LastError for more information!");

	return name.data();
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

bool ModuleListNode::operator!=(const ModuleListNode& right) const
{
	return !operator==(right);
}
}
