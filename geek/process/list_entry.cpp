#include "list_entry.h"
#include <geek/process/process.h>
#include <winnt.h>

namespace geek {
ListEntry::ListEntry(Process* proc, uint64_t addr)
	: proc_(proc), addr_(addr)
{
	if (proc_->IsX86())
	{
		LIST_ENTRY32 entry{};
		if (!proc_->ReadMemory(addr, &entry, sizeof(LIST_ENTRY32))) {
			return;
		}
		flink_ = entry.Flink;
		blink_ = entry.Blink;
	}
	else
	{
		LIST_ENTRY64 entry{};
		if (!proc_->ReadMemory(addr, &entry, sizeof(LIST_ENTRY64))) {
			return;
		}
		flink_ = entry.Flink;
		blink_ = entry.Blink;
	}
}

bool ListEntry::IsValid() const
{
	return proc_ && addr_;
}

ListEntry ListEntry::Flink() const
{
	return { proc_, flink_ };
}

ListEntry ListEntry::Blink() const
{
	return { proc_, blink_ };
}
}
