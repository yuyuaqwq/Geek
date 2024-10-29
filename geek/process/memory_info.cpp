#include <geek/process/memory_info.h>

namespace geek {
MemoryInfo::MemoryInfo(const MEMORY_BASIC_INFORMATION32& entry)
{
	base = entry.BaseAddress;
	size = entry.RegionSize;
	protect = entry.Protect;
	state = entry.State;
}

MemoryInfo::MemoryInfo(const MEMORY_BASIC_INFORMATION64& entry)
{
	base = entry.BaseAddress;
	size = entry.RegionSize;
	protect = entry.Protect;
	state = entry.State;
}
}
