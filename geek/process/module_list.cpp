#include <geek/process/module_list.h>

#include <cassert>

#include "list_entry.h"
#include <geek/process/process.h>
#include <geek/utils/converter.h>

namespace geek {
ModuleList::ModuleList(Process* proc)
	: proc_(proc)
{
}

std::optional<PEB_LDR_DATA32> ModuleList::PebLdrData32() const
{
	if (!ldr32_)
	{
		auto peb = proc_->Peb32();
		if (!peb)
			return std::nullopt;
		ldr32_ = proc_->ReadMemoryToValue<PEB_LDR_DATA32>(peb->Ldr);
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
		ldr64_ = proc_->ReadMemoryToValue<PEB_LDR_DATA64>(peb->Ldr);
	}
	return ldr64_;
}

uint64_t ModuleList::AddressOfFirstLink() const
{
	if (IsX32())
	{
		auto ldr = PebLdrData32();
		return ldr->InLoadOrderModuleList.Flink;
	}
	else
	{
		auto ldr = PebLdrData64();
		return ldr->InLoadOrderModuleList.Flink;
	}
}

uint64_t ModuleList::AddressOfLastLink() const
{
	ListEntry entry{ proc_, AddressOfFirstLink() };
	return entry.Blink().addr();
}

bool ModuleList::IsX32() const
{
	return proc_->IsX32();
}

bool ModuleList::IsValid() const
{
	if (proc_ == nullptr)
		return false;
	if (IsX32())
		return PebLdrData32().has_value();
	else
		return PebLdrData64().has_value();
}

ModuleListNode ModuleList::begin() const
{
	assert(IsValid());
	return { const_cast<ModuleList*>(this), AddressOfFirstLink() };
}

ModuleListNode ModuleList::end() const
{
	assert(IsValid());
	return { const_cast<ModuleList*>(this), AddressOfLastLink() };
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
	return entry_ == owner_->AddressOfLastLink();
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
		ldte32_ = owner_->proc_->ReadMemoryToValue<LDR_DATA_TABLE_ENTRY32>(entry_);
	}
	return ldte32_;
}

std::optional<LDR_DATA_TABLE_ENTRY64> ModuleListNode::LdrDataTableEntry64() const
{
	if (!ldte64_) {
		ldte64_ = owner_->proc_->ReadMemoryToValue<LDR_DATA_TABLE_ENTRY64>(entry_);
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
	assert(IsValid());

	auto f = ListEntry(owner_->proc_, entry_).Flink();
	entry_ = f.addr();

	ldte32_.reset();
	ldte64_.reset();

	return *this;
}

ModuleListNode ModuleListNode::operator++(int)
{
	auto tmp = *this;
	++*this;
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

std::wstring ModuleListNode::DebugName() const
{
	if (!IsValid())
		return L"<Invalid>";
	return L"[Addr:0x" + Convert::ToHexWString(DllBase(), IsX32() ? 4 : 8)
		+ L" Size:" + Convert::ToHexWString(SizeOfImage(), 4) + L"] "
		+ BaseDllName();
}
}
