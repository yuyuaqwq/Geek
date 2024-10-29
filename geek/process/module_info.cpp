#include <geek/process/module_info.h>

namespace geek {
ModuleInfo::ModuleInfo(uint64_t base_, uint32_t size_)
{
	base = base_;
	size = size_;
	entry_point = 0;
}

ModuleInfo::ModuleInfo(const LDR_DATA_TABLE_ENTRY64& entry, const std::wstring& base_name_,
	const std::wstring& full_name_)
{
	base = entry.DllBase;
	size = entry.SizeOfImage;
	base_name = base_name_;
	full_name = full_name_;
	entry_point = entry.EntryPoint;
}

ModuleInfo::ModuleInfo(const LDR_DATA_TABLE_ENTRY32& entry, const std::wstring& base_name_,
	const std::wstring& full_name_)
{
	base = entry.DllBase;
	size = entry.SizeOfImage;
	base_name = base_name_;
	full_name = full_name_;
	entry_point = entry.EntryPoint;
}
}
