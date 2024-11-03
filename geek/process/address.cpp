#include <geek/process/address.h>
#include <geek/process/process.h>

namespace geek {
Address::Address(Process* proc, uint64_t addr)
	: proc_(proc), addr_(addr)
{
}

bool Address::Read(void* buf, size_t len) const
{
	return proc_->ReadMemory(addr_, buf, len);
}

std::optional<std::vector<uint8_t>> Address::Read(size_t len) const
{
	return proc_->ReadMemory(addr_, len);
}

bool Address::Write(const void* buf, size_t len, bool force) const
{
	return proc_->WriteMemory(addr_, buf, len, force);
}
}
