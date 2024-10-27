#include <geek/process/process_info.h>

namespace geek {
ProcessInfo::ProcessInfo(const PROCESSENTRY32W& entry)
{
	process_id = entry.th32ProcessID;
	parent_process_id = entry.th32ParentProcessID;
	process_name = entry.szExeFile;
}
}
