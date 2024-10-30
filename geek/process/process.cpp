#include <geek/process/process.h>

#include <regex>
#include <algorithm>
#include <array>
#include <mutex>
#include <cstddef>
#include <geek/process/ntinc.h>
#include <geek/utils/converter.h>
#include <geek/utils/searcher.h>

namespace geek {
namespace {
// template<typename IMAGE_THUNK_DATA_T>
// bool RepairImportAddressTableFromModule(Process& proc, Image* image, _IMAGE_IMPORT_DESCRIPTOR* import_descriptor, uint64_t import_image_base, bool skip_not_loaded) {
// 	IMAGE_THUNK_DATA_T* import_name_table = (IMAGE_THUNK_DATA_T*)image->RvaToPoint(import_descriptor->OriginalFirstThunk);
// 	IMAGE_THUNK_DATA_T* import_address_table = (IMAGE_THUNK_DATA_T*)image->RvaToPoint(import_descriptor->FirstThunk);
// 	Image import_image;
// 	if (import_image_base) {
// 		auto import_image_res = proc.LoadImageFromImageBase(import_image_base);
// 		if (!import_image_res) {
// 			return false;
// 		}
// 		import_image = std::move(*import_image_res);
// 	}
// 	else if (!skip_not_loaded) {
// 		return false;
// 	}
// 	for (; import_name_table->u1.ForwarderString; import_name_table++, import_address_table++) {
// 		if (!import_image_base) {
// 			import_address_table->u1.Function = import_address_table->u1.Function = 0x1234567887654321;
// 			continue;
// 		}
// 		uint32_t export_rva;
// 		if (import_name_table->u1.Ordinal >> (sizeof(import_name_table->u1.Ordinal) * 8 - 1) == 1) {
// 			auto export_addr = proc.GetExportProcAddress(&import_image, (char*)((import_name_table->u1.Ordinal << 1) >> 1));
// 			if (!export_addr) return false;
// 			import_address_table->u1.Function = export_addr.value();
// 		}
// 		else {
// 			IMAGE_IMPORT_BY_NAME* func_name = (IMAGE_IMPORT_BY_NAME*)image->RvaToPoint(import_name_table->u1.AddressOfData);
// 			auto export_addr = proc.GetExportProcAddress(&import_image, (char*)func_name->Name);
// 			if (!export_addr) return false;
// 			import_address_table->u1.Function = export_addr.value();
// 		}
// 		//import_address_table->u1.Function = import_module_base + export_rva;
// 	}
// 	return true;
// }

class CallPageX86 {
public:
	CallPageX86(Process* process, bool sync)
		: process_(process) {
		auto res = process->AllocMemory(NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (res) {
			exec_page_ = *res;
			process->CallGenerateCodeX86(exec_page_, sync);
		}
	}

	~CallPageX86() {
		Close();
	}

	CallPageX86(const CallPageX86&) = delete;
	void operator=(const CallPageX86&) = delete;

	CallPageX86(CallPageX86&& rv) {
		Close();
		process_ = rv.process_;
		exec_page_ = rv.exec_page_;
		rv.exec_page_ = 0;
	}

	uint64_t exec_page() const { return exec_page_; }


private:
	void Close() {
		if (exec_page_) {
			process_->FreeMemory(exec_page_);
			exec_page_ = 0;
		}
	}
private:
	Process* process_;
	uint64_t exec_page_ = 0;
};
struct ExecPageHeaderX86 {
	uint32_t call_addr;
	uint32_t context_addr;
	uint32_t stack_count;
	uint32_t stack_addr;
};

class CallPageAmd64 {
public:
	CallPageAmd64(Process* process, bool sync)
		: process_(process) {
		auto res = process->AllocMemory(NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (res) {
			exec_page_ = *res;
			process->CallGenerateCodeAmd64(exec_page_, sync);
		}
	}

	~CallPageAmd64() {
		Close();
	}

	CallPageAmd64(const CallPageAmd64&) = delete;
	void operator=(const CallPageAmd64&) = delete;

	CallPageAmd64(CallPageAmd64&& rv) {
		Close();
		process_ = rv.process_;
		exec_page_ = rv.exec_page_;
		rv.exec_page_ = 0;
	}

	uint64_t exec_page() const { return exec_page_; }


private:
	void Close() {
		if (exec_page_) {
			process_->FreeMemory(exec_page_);
			exec_page_ = 0;
		}
	}
private:
	Process* process_;
	uint64_t exec_page_ = 0;
};


// enum class SignElementType {
// 	kNone,
// 	kWhole,
// 	kVague
// };
//
// struct SignElement {
// 	SignElementType type;
// 	size_t length;
// 	std::vector<unsigned char> data;
// };
//
// unsigned int DecStringToUInt(const std::string& str, size_t* i = nullptr, const unsigned char* end_char_arr = nullptr, size_t end_char_arr_size = 0) {
// 	unsigned int sum = 0;
// 	if (!i) {
// 		size_t j;
// 		i = &j;
// 	}
// 	for (*i = 0; *i < str.length(); ++*i) {
// 		unsigned char c = str[*i];
// 		if (c >= 0x30 && c <= 0x39) {
// 			c -= 0x30;
// 			sum = sum * 10 + c;
// 		}
// 		else if (end_char_arr) {
// 			for (size_t j = 0; j < end_char_arr_size; ++j) {
// 				if (c == end_char_arr[j]) return sum;
// 			}
// 		}
// 		else break;
//
// 	}
// 	return sum;
// }
//
// int __cdecl memcmp_ex(const void* buf1, const void* buf2, size_t size) {
// 	const char* buf1_ = (const char*)buf1;
// 	const char* buf2_ = (const char*)buf2;
//
// 	__try {
// 		for (int i = 0; i < size; i++) {
// 			if (buf1_[i] != buf2_[i]) {
// 				return i;
// 			}
// 		}
// 		return -1;
//
// 	}
// 	__except (1) {
// 		return -2;
// 	}
// }
//
//
// /*
// * "48 &?? ?? 65*20 88"
// * &表示返回的地址以此为准
// * *20表示重复20次，是十进制
// * ??表示模糊匹配
// */
// size_t StringToElement(const std::string& hex_string_data, std::vector<SignElement>& signature, size_t& offset) {
// 	bool first = true;
// 	unsigned char sum = 0;
// 	SignElement temp_signature_element;
// 	temp_signature_element.length = 0;
// 	SignElementType oldType = SignElementType::kNone, newType = SignElementType::kNone;
// 	size_t total_length = 0;
//
// 	for (size_t i = 0; i < hex_string_data.length(); ++i) {
// 		unsigned char c = hex_string_data[i];
// 		bool validChar = true;
// 		if (c >= '0' && c <= '9') {
// 			c -= '0';
// 			newType = SignElementType::kWhole;
// 		}
// 		else if (c >= 'a' && c <= 'f') {
// 			c = c - 'a' + 10;
// 			newType = SignElementType::kWhole;
// 		}
// 		else if (c >= 'A' && c <= 'F') {
// 			c = c - 'A' + 10;
// 			newType = SignElementType::kWhole;
// 		}
// 		else if (c == '?') {
// 			newType = SignElementType::kVague;
// 		}
// 		else {
// 			if (c == '&') {
// 				offset = total_length + temp_signature_element.length;
// 			}
// 			else if (c == '*' && i + 1 < hex_string_data.length()) {
// 				size_t countInt;
// 				unsigned int lenInt = DecStringToUInt(&hex_string_data[i] + 1, &countInt) - 1;
// 				if (countInt) {
// 					if (oldType == SignElementType::kWhole && temp_signature_element.data.size() > 0) {
// 						unsigned char repC = temp_signature_element.data[temp_signature_element.data.size() - 1];
// 						for (size_t j = 0; j < lenInt; ++j) {
// 							temp_signature_element.data.push_back(repC);
// 						}
// 					}
// 					temp_signature_element.length += lenInt;
// 					i += countInt;
// 				}
//
// 			}
// 			validChar = false;
// 			goto _PushChar;
// 		}
//
// 		if (oldType == SignElementType::kNone) {
// 			oldType = newType;
// 		}
//
// 		else if (oldType != newType) {
// 			temp_signature_element.type = oldType;
// 			total_length += temp_signature_element.length;
// 			signature.push_back(temp_signature_element);
//
// 			oldType = newType;
// 			temp_signature_element.length = 0;
// 			temp_signature_element.data.clear();
// 		}
//
// 	_PushChar:
// 		if (oldType == SignElementType::kWhole) {
// 			if (first && validChar) {
// 				sum = c << 4;
// 				first = false;
// 			}
// 			else if (!first) {
// 				first = true;
// 				validChar ? sum += c : sum >>= 4;
// 				temp_signature_element.data.push_back(sum);
// 				++temp_signature_element.length;
// 			}
// 		}
//
// 		else if (oldType == SignElementType::kVague) {
// 			if (first && validChar) {
// 				first = false;
// 			}
// 			else if (!first) {
// 				first = true;
// 				++temp_signature_element.length;
// 			}
// 		}
//
// 	}
//
// 	if (!first) {
// 		if (oldType == SignElementType::kWhole) {
// 			temp_signature_element.data.push_back(sum >> 4);
// 		}
// 		++temp_signature_element.length;
// 	}
//
// 	if (temp_signature_element.length > 0 || temp_signature_element.data.size() > 0) {
// 		temp_signature_element.type = oldType;
// 		total_length += temp_signature_element.length;
// 		signature.push_back(temp_signature_element);
// 	}
//
// 	return total_length;
// }


struct ExecPageHeaderAmd64 {
	uint64_t call_addr;
	uint64_t context_addr;
	uint64_t stack_count;
	uint64_t stack_addr;
};


typedef VOID(NTAPI* PIMAGE_TLS_CALLBACK32)(uint32_t DllHandle, DWORD Reason, PVOID Reserved);
typedef VOID(NTAPI* PIMAGE_TLS_CALLBACK64)(uint64_t DllHandle, DWORD Reason, PVOID Reserved);
typedef BOOL(WINAPI* DllEntryProc32)(uint32_t hinstDLL, DWORD fdwReason, uint32_t lpReserved);
typedef BOOL(WINAPI* DllEntryProc64)(uint64_t hinstDLL, DWORD fdwReason, uint64_t lpReserved);
typedef int (WINAPI* ExeEntryProc)(void);
}

std::optional<Process> Process::Open(DWORD pid, DWORD desiredAccess)
{
	auto hProcess = OpenProcess(desiredAccess, FALSE, pid);
	if (hProcess == NULL) {
		return {};
	}
	return Process{ UniqueHandle(hProcess) };
}

std::optional<Process> Process::Open(std::wstring_view process_name, DWORD desiredAccess, size_t count)
{
	auto pid = GetProcessIdByProcessName(process_name, count);
	if (!pid) {
		return {};
	}
	return Open(pid.value(), desiredAccess);
}

std::optional<std::tuple<Process, Thread>> Process::Create(std::wstring_view command, BOOL inheritHandles,
	DWORD creationFlags)
{
	std::wstring command_ = command.data();
	STARTUPINFOW startupInfo{ sizeof(startupInfo) };
	PROCESS_INFORMATION processInformation{ 0 };
	if (!CreateProcessW(NULL, (LPWSTR)command_.c_str(), NULL, NULL, inheritHandles, creationFlags, NULL, NULL, &startupInfo, &processInformation)) {
		return {};
	}
	return std::tuple{ Process{ UniqueHandle{ processInformation.hProcess } },  Thread{ UniqueHandle{ processInformation.hThread } } };
}

std::optional<std::tuple<Process, Thread>> Process::CreateByToken(std::wstring_view tokenProcessName,
	std::wstring_view command, BOOL inheritHandles, DWORD creationFlags, STARTUPINFOW* si, PROCESS_INFORMATION* pi)
{
	HANDLE hToken_ = NULL;
	auto pid = GetProcessIdByProcessName(tokenProcessName);
	if (!pid) {
		return {};
	}
	UniqueHandle hProcess{ OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid.value()) };
	OpenProcessToken(*hProcess, TOKEN_ALL_ACCESS, &hToken_);
	if (hToken_ == NULL) {
		return {};
	}
	UniqueHandle hToken{ hToken_ };

	if (!si) {
		STARTUPINFOW tempSi{ 0 };
		si = &tempSi;
	}
	if (!pi) {
		PROCESS_INFORMATION tempPi{ 0 };
		pi = &tempPi;
	}
	si->cb = sizeof(STARTUPINFO);
	// si->lpDesktop = L"winsta0\\default";
	si->dwFlags |= STARTF_USESHOWWINDOW;
	si->wShowWindow |= SW_HIDE;
	std::wstring command_copy = command.data();
	BOOL ret = CreateProcessAsUserW(*hToken, NULL, (LPWSTR)command_copy.c_str(), NULL, NULL, inheritHandles, creationFlags | NORMAL_PRIORITY_CLASS, NULL, NULL, si, pi);
	if (!ret) {
		return {};
	}
	return std::tuple { Process{ UniqueHandle(pi->hProcess) }, Thread{ UniqueHandle(pi->hThread) } };
}

std::optional<std::vector<uint64_t>> Process::SearchSigEx(const char* pattern, size_t pattern_size, uint64_t start_address,
	size_t size, size_t max_match_size) const
{
	if (auto opt = ReadMemory(start_address, size); opt)
	{
		std::vector<uint64_t> total;
		auto m = std::move(*opt);
		auto res = Searcher::SearchMemory(pattern, pattern_size, m.data(), m.size(), max_match_size);
		if (res.empty())
			return std::nullopt;

		for (auto i : res)
			total.push_back(start_address + i);
		return total;
	}
	return std::nullopt;
}

std::optional<std::vector<uint64_t>> Process::SearchSig(std::string_view hex_string, uint64_t start_address, size_t size) const
{
	std::vector<char> pattern;
	for (auto h : hex_string)
	{
		pattern.push_back('\\');
		pattern.push_back('x');
		pattern.push_back(h);
	}
	// 结尾需要个.*匹配
	pattern.push_back('.');
	pattern.push_back('*');
	return SearchSigEx(pattern.data(), pattern.size(), start_address, size, (hex_string.size() + 1) / 2);
	// std::vector<SignElement> signature;
	// size_t offset = 0, total_len = StringToElement(hex_string_data, signature, offset);
	//
	// size_t signature_size = signature.size();
	// if (!signature_size) return {};
	//
	// uint64_t base = 0;
	// std::optional<std::vector<uint8_t>> buf;
	// if (!IsCur()) {
	// 	buf = ReadMemory(start_address, size);
	// 	if (!buf) {
	// 		return {};
	// 	}
	// 	uint64_t new_start_address = (uint64_t)buf.value().data();
	// 	base = ((uint64_t)start_address - (uint64_t)new_start_address);
	// 	start_address = new_start_address;
	// }
	//
	// for (size_t i = 0; i < size; ++i) {
	// 	uint64_t cur_pos = start_address + i;
	// 	if (base + i == 0x13cdce0) {
	// 		printf("???");
	// 	}
	// 	uint64_t ret_pos = cur_pos;
	// 	if (i + total_len > size) break;
	// 	bool match = true;
	// 	for (size_t j = 0; j < signature_size; ++j) {
	// 		size_t length = signature[j].length;
	// 		if (signature[j].type == SignElementType::kWhole) {
	// 			if (IsBadReadPtr((void*)cur_pos, length)) {
	// 				match = false;
	// 				break;
	// 			}
	// 			int ret = memcmp((void*)cur_pos, signature[j].data.data(), length);
	// 			if (ret != 0) {
	// 				match = false;
	// 				break;
	// 			}
	// 		}
	// 		cur_pos = cur_pos + length;
	// 	}
	// 	if (match) {
	// 		return (base + ret_pos + offset);
	// 	}
	// }
	// return {};
}

bool Process::Terminate(uint32_t exitCode)
{
	bool ret = ::TerminateProcess(Handle(), exitCode);
	process_handle_.Reset();
	return ret;
}

bool Process::SetDebugPrivilege(bool IsEnable) const
{
	DWORD LastError = 0;
	HANDLE TokenHandle = 0;

	if (!OpenProcessToken(Handle(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle)) {
		LastError = GetLastError();
		if (TokenHandle) {
			CloseHandle(TokenHandle);
		}
		return LastError;
	}
	TOKEN_PRIVILEGES TokenPrivileges;
	memset(&TokenPrivileges, 0, sizeof(TOKEN_PRIVILEGES));
	LUID v1;
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &v1)) {
		LastError = GetLastError();
		CloseHandle(TokenHandle);
		return LastError;
	}
	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Luid = v1;
	if (IsEnable) {
		TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else {
		TokenPrivileges.Privileges[0].Attributes = 0;
	}
	AdjustTokenPrivileges(TokenHandle, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	LastError = GetLastError();
	CloseHandle(TokenHandle);
	return LastError;
}

HANDLE Process::Handle() const noexcept
{
	if (this == nullptr) {
		return kCurrentProcess;
	}
	return *process_handle_;
}

DWORD Process::ProcId() const noexcept
{
	return GetProcessId(Handle());
}

bool Process::IsX86() const noexcept
{
	auto handle = Handle();

	::BOOL IsWow64;
	if (!::IsWow64Process(handle, &IsWow64)) {
		return false;
	}

	if (IsWow64) {
		return true;
	}

	::SYSTEM_INFO SystemInfo = { 0 };
	::GetNativeSystemInfo(&SystemInfo);
	if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
		return false;
	}
	else if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
		return true;
	}
	return false;

}

bool Process::IsCur() const
{
	return this == nullptr || *process_handle_ == kCurrentProcess;
}

std::optional<uint64_t> Process::AllocMemory(uint64_t addr, size_t len, DWORD type, DWORD protect) const
{
	if (ms_wow64.Wow64Operation(Handle())) {
		auto ptr = ms_wow64.VirtualAllocEx64(Handle(), (DWORD64)addr, len, type, protect);
		if (ptr == 0) {
			return {};
		}
		return static_cast<uint64_t>(ptr);
	}
	auto ptr = VirtualAllocEx(Handle(), (LPVOID)addr, len, type, protect);
	if (ptr == NULL) {
		return {};
	}
	return reinterpret_cast<uint64_t>(ptr);
}

std::optional<uint64_t> Process::AllocMemory(size_t len, DWORD type, DWORD protect) const
{
	return AllocMemory(NULL, len, type, protect);
}

bool Process::FreeMemory(uint64_t addr, size_t size, DWORD type) const
{
	if (ms_wow64.Wow64Operation(Handle())) {
		return ms_wow64.VirtualFreeEx64(Handle(), (DWORD64)addr, size, type);
	}
	return VirtualFreeEx(Handle(), (LPVOID)addr, size, type);
}

bool Process::ReadMemory(uint64_t addr, void* buf, size_t len) const
{
	SIZE_T readByte;
	if (IsCur()) {
		memcpy(buf, (void*)addr, len);
		return true;
	}
	if (ms_wow64.Wow64Operation(Handle())) {
		HMODULE NtdllModule = ::GetModuleHandleW(L"ntdll.dll");
		pfnNtWow64ReadVirtualMemory64 NtWow64ReadVirtualMemory64 = (pfnNtWow64ReadVirtualMemory64)::GetProcAddress(NtdllModule, "NtWow64ReadVirtualMemory64");
		if (!NT_SUCCESS(NtWow64ReadVirtualMemory64(Handle(), addr, buf, len, NULL))) {
			return false;
		}
	}
	else {
		if (!::ReadProcessMemory(Handle(), (void*)addr, buf, len, &readByte)) {
			// throw ProcessException(ProcessException::Type::kReadProcessMemoryError);
			return false;
		}
	}
	return true;
}

std::optional<std::vector<uint8_t>> Process::ReadMemory(uint64_t addr, size_t len) const
{
	std::vector<uint8_t> buf;
	buf.resize(len, 0);
	if (!ReadMemory(addr, buf.data(), len)) {
		return {};
	}
	return buf;
}

bool Process::WriteMemory(uint64_t addr, const void* buf, size_t len, bool force) const
{
	DWORD oldProtect;
	if (force) {
		if (!SetMemoryProtect(addr, len, PAGE_EXECUTE_READWRITE, &oldProtect)) {
			return false;
		}
	}
	SIZE_T readByte;
	bool success = true;
	if (ms_wow64.Wow64Operation(Handle())) {
		HMODULE NtdllModule = GetModuleHandleW(L"ntdll.dll");
		pfnNtWow64QueryInformationProcess64 NtWow64QueryInformationProcess64 = (pfnNtWow64QueryInformationProcess64)GetProcAddress(NtdllModule, "NtWow64QueryInformationProcess64");
		pfnNtWow64WriteVirtualMemory64 NtWow64WriteVirtualMemory64 = (pfnNtWow64WriteVirtualMemory64)GetProcAddress(NtdllModule, "NtWow64WriteVirtualMemory64");
		if (!NT_SUCCESS(NtWow64WriteVirtualMemory64(Handle(), addr, (PVOID)buf, len, NULL))) {
			success = false;
		}
	}
	else {
		if (Handle() == kCurrentProcess) {
			memcpy((void*)addr, buf, len);
		}
		else if (!::WriteProcessMemory(Handle(), (void*)addr, buf, len, &readByte)) {
			success = false;
		}
	}
	if (force) {
		SetMemoryProtect(addr, len, oldProtect, &oldProtect);
	}
	return true;
}

std::optional<uint64_t> Process::WriteMemory(const void* buf, size_t len, DWORD protect)
{
	auto mem = AllocMemory(len, (DWORD)MEM_COMMIT, protect);
	if (!mem) {
		return {};
	}
	WriteMemory(mem.value(), buf, len);
	return mem;
}

bool Process::SetMemoryProtect(uint64_t addr, size_t len, DWORD newProtect, DWORD* oldProtect) const
{
	bool success = false;
	if (ms_wow64.Wow64Operation(Handle())) {
		success = ms_wow64.VirtualProtectEx64(Handle(), (DWORD64)addr, len, newProtect, oldProtect);
	}
	else {
		success = ::VirtualProtectEx(Handle(), (LPVOID)addr, len, newProtect, oldProtect);
	}
	return success;
}

std::optional<MemoryInfo> Process::GetMemoryInfo(uint64_t addr) const
{
	uint64_t size;
	MEMORY_BASIC_INFORMATION    memInfo = { 0 };
	MEMORY_BASIC_INFORMATION64    memInfo64 = { 0 };
	if (ms_wow64.Wow64Operation(Handle())) {
		size = geek::Wow64::VirtualQueryEx64(Handle(), addr, &memInfo64, sizeof(memInfo64));
		if (size != sizeof(memInfo64)) { return {}; }
		return MemoryInfo(memInfo64);
	}
	else {
		size_t size = ::VirtualQueryEx(Handle(), (PVOID)addr, &memInfo, sizeof(memInfo));
		if (size != sizeof(memInfo)) { return {}; }
		if (IsX86()) {
			return MemoryInfo(*(MEMORY_BASIC_INFORMATION32*)&memInfo);
		}
		else {
			return MemoryInfo(*(MEMORY_BASIC_INFORMATION64*)&memInfo);
		}
	}
}

std::optional<std::vector<MemoryInfo>> Process::GetMemoryInfoList() const
{
	std::vector<MemoryInfo> memory_block_list;

	memory_block_list.reserve(200);
	/*
        typedef struct _SYSTEM_INFO {
        union {
        DWORD dwOemId;
        struct {
        WORD wProcessorArchitecture;
        WORD wReserved;
        } DUMMYSTRUCTNAME;
        } DUMMYUNIONNAME;
        DWORD     dwPageSize;
        LPVOID    lpMinimumApplicationAddress;
        LPVOID    lpMaximumApplicationAddress;
        DWORD_PTR dwActiveProcessorMask;
        DWORD     dwNumberOfProcessors;
        DWORD     dwProcessorType;
        DWORD     dwAllocationGranularity;
        WORD        wProcessorLevel;
        WORD        wProcessorRevision;
        } SYSTEM_INFO, *LPSYSTEM_INFO;
        */

	uint64_t p = 0;
	MEMORY_BASIC_INFORMATION mem_info = { 0 };
	MEMORY_BASIC_INFORMATION64 mem_info64 = { 0 };
	while (true) {
		uint64_t size;
		if (ms_wow64.Wow64Operation(Handle())) {
			size = geek::Wow64::VirtualQueryEx64(Handle(), p, &mem_info64, sizeof(mem_info64));
			if (size != sizeof(mem_info64)) { break; }
			memory_block_list.push_back(MemoryInfo{ mem_info64 });
			p += mem_info64.RegionSize;
		}
		else {
			size_t size = ::VirtualQueryEx(Handle(), (PVOID)p, &mem_info, sizeof(mem_info));
			if (size != sizeof(mem_info)) { break; }
			if (IsX86()) {
				memory_block_list.push_back(MemoryInfo{ *(MEMORY_BASIC_INFORMATION32*)&mem_info });
			}
			else {
				memory_block_list.push_back(MemoryInfo{ *(MEMORY_BASIC_INFORMATION64*)&mem_info });
			}
			p += mem_info.RegionSize;
		}
            
	}
	return memory_block_list;
}

bool Process::ScanMemoryInfoList(const std::function<bool(uint64_t raw_addr, uint8_t* addr, size_t size)>& callback,
	bool include_module) const
{
	bool success = false;
	do {
		auto module_list_res = GetModuleInfoList();
		if (!module_list_res) {
			return false;
		}
		auto& module_list = module_list_res.value();
		auto vec_res = GetMemoryInfoList();
		if (!vec_res) {
			return false;
		}
		auto& vec = vec_res.value();
		size_t sizeSum = 0;

		for (int i = 0; i < vec.size(); i++) {
			if (vec[i].protect & PAGE_NOACCESS || !vec[i].protect) {
				continue;
			}

			if (include_module == false) {
				bool is_module = false;
				for (int j = 0; j < module_list.size(); j++) {
					if (vec[i].base >= module_list[j].base && vec[i].base < module_list[j].base + module_list[j].base) {
						is_module = true;
						break;
					}
				}
				if (!(!is_module && vec[i].protect & PAGE_READWRITE && vec[i].state & MEM_COMMIT)) {
					continue;
				}
			}

			auto temp_buff = ReadMemory(vec[i].base, vec[i].size);
			if (!temp_buff) {
				continue;
			}
                
			if (callback(vec[i].base, temp_buff.value().data(), temp_buff.value().size())) {
				break;
			}
			sizeSum += vec[i].size;
		}
		success = true;
	} while (false);
	return success;
}

std::optional<std::wstring> Process::GetCommandLineStr() const
{
	typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
		HANDLE ProcessHandle,
		DWORD ProcessInformationClass,
		PVOID ProcessInformation,
		DWORD ProcessInformationLength,
		PDWORD ReturnLength
	);
        
	if (IsX86()) {
		UNICODE_STRING32 commandLine;
		_NtQueryInformationProcess NtQuery = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
		if (!NtQuery) {
			return {};
		}

		PROCESS_BASIC_INFORMATION32 pbi;
		NTSTATUS isok = NtQuery(Handle(), ProcessBasicInformation, &pbi, sizeof(RTL_USER_PROCESS_PARAMETERS32), NULL);
		if (!NT_SUCCESS(isok)) {
			return {};
		}

		PEB32 peb;
		RTL_USER_PROCESS_PARAMETERS32 upps;
		PRTL_USER_PROCESS_PARAMETERS32 rtlUserProcParamsAddress;
		if (!ReadMemory((uint64_t)&(((PEB32*)(pbi.PebBaseAddress))->ProcessParameters), &rtlUserProcParamsAddress, sizeof(rtlUserProcParamsAddress))) {
			return {};
		}

		if (!ReadMemory((uint64_t)&(rtlUserProcParamsAddress->CommandLine), &commandLine, sizeof(commandLine))) {
			return {};
		}

		std::wstring buf(commandLine.Length, L' ');
		if (!ReadMemory((uint64_t)commandLine.Buffer,
		                (void*)buf.data(), commandLine.Length)) {
			return {};
		}
		return buf;
	}
	else {

		UNICODE_STRING64 commandLine;
		PROCESS_BASIC_INFORMATION64 pbi;
		HMODULE NtdllModule = GetModuleHandleA("ntdll.dll");
		if (ms_wow64.Wow64Operation(Handle())) {
			pfnNtWow64QueryInformationProcess64 NtWow64QueryInformationProcess64 = (pfnNtWow64QueryInformationProcess64)GetProcAddress(NtdllModule, "NtWow64QueryInformationProcess64");
			if (!NT_SUCCESS(NtWow64QueryInformationProcess64(Handle(), ProcessBasicInformation, &pbi, sizeof(pbi), NULL))) {
				return {};
			}
		}
		else {
			pfnNtQueryInformationProcess NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(NtdllModule, "NtQueryInformationProcess");
			if (!NT_SUCCESS(NtQueryInformationProcess(Handle(), ProcessBasicInformation, &pbi, sizeof(pbi), NULL))) {
				return {};
			}
		}

		PEB64 peb;
		RTL_USER_PROCESS_PARAMETERS64 upps;
		PRTL_USER_PROCESS_PARAMETERS64 rtlUserProcParamsAddress;
		if (!ReadMemory((uint64_t) & (((PEB64*)(pbi.PebBaseAddress))->ProcessParameters), &rtlUserProcParamsAddress, sizeof(rtlUserProcParamsAddress))) {
			return {};
		}

		if (!ReadMemory((uint64_t) & (rtlUserProcParamsAddress->CommandLine), &commandLine, sizeof(commandLine))) {
			return {};
		}

		std::wstring buf(commandLine.Length, L' ');
		if (!ReadMemory((uint64_t)commandLine.Buffer,
		                (void*)buf.data(), commandLine.Length)) {
			return {};
		}
		return buf;
	}
}

std::optional<uint16_t> Process::LockAddress(uint64_t addr) const
{
	uint16_t instr;
	if (!ReadMemory(addr, &instr, 2)) {
		return {};
	}
	unsigned char jmpSelf[] = { 0xeb, 0xfe };
	if (!WriteMemory(addr, jmpSelf, 2, true)) {
		return {};
	}
	return instr;
}

bool Process::UnlockAddress(uint64_t addr, uint16_t instr) const
{
	return WriteMemory(addr, &instr, 2, true);
}

std::optional<Thread> Process::CreateThread(uint64_t start_routine, uint64_t parameter, DWORD dwCreationFlags) const
{
	DWORD thread_id = 0;
	HANDLE thread_handle = NULL;
	if (IsCur()) {
		thread_handle = ::CreateThread(NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(start_routine), reinterpret_cast<PVOID64>(parameter), dwCreationFlags, &thread_id);
	}
	else {
		if (ms_wow64.Wow64Operation(Handle())) {
			auto ntdll64 = ms_wow64.GetNTDLL64();
			auto RtlCreateUserThread = ms_wow64.GetProcAddress64(ntdll64, "RtlCreateUserThread");
			auto ntdll_RtlExitThread = ms_wow64.GetProcAddress64(ntdll64, "RtlExitUserThread");

			unsigned char shell_code[] = {
				0x48, 0x89, 0x4c, 0x24, 0x08,                               // mov       qword ptr [rsp+8],rcx 
				0x57,                                                       // push      rdi
				0x48, 0x83, 0xec, 0x20,                                     // sub       rsp,20h
				0x48, 0x8b, 0xfc,                                           // mov       rdi,rsp
				0xb9, 0x08, 0x00, 0x00, 0x00,                               // mov       ecx,8
				0xb8, 0xcc, 0xcc, 0xcc, 0xcc,                               // mov       eac,0CCCCCCCCh
				0xf3, 0xab,                                                 // rep stos  dword ptr [rdi]
				0x48, 0x8b, 0x4c, 0x24, 0x30,                               // mov       rcx,qword ptr [__formal]
				0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rcx,   parameter
				0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rax,0 
				0xff, 0xd0,                                                 // call      rax    start_routine
				0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rcx,0
				0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rax,0
				0xff, 0xd0                                                  // call      rax
                    
			};

			auto buf_addr = AllocMemory(size_t{ 4096 }, DWORD{ MEM_RESERVE | MEM_COMMIT }, PAGE_EXECUTE_READWRITE);
			if (!buf_addr) {
				return {};
			}

			//r8
			memcpy(shell_code + 32, &parameter, sizeof(parameter));

			memcpy(shell_code + 42, &start_routine, sizeof(start_routine));

			//RtlExitUserThread
			memcpy(shell_code + 64, &ntdll_RtlExitThread, sizeof(DWORD64));
			size_t write_size = 0;

			if (!WriteMemory(*buf_addr, shell_code, sizeof(shell_code))) {
				FreeMemory(*buf_addr);
				return {};
			}

			struct {
				DWORD64 UniqueProcess;
				DWORD64 UniqueThread;
			} client_id { 0 };

			auto error = ms_wow64.X64Call(RtlCreateUserThread, 10,
			                              reinterpret_cast<DWORD64>(Handle()), 
			                              static_cast<DWORD64>(NULL), static_cast<DWORD64>(FALSE),
			                              static_cast<DWORD64>(0), static_cast<DWORD64>(NULL), static_cast<DWORD64>(NULL),
			                              static_cast<DWORD64>(*buf_addr), static_cast<DWORD64>(0),
			                              reinterpret_cast<DWORD64>(&thread_handle),
			                              reinterpret_cast<DWORD64>(&client_id));
                
			if (thread_handle) {
				::WaitForSingleObject(thread_handle, INFINITE);
			}

			FreeMemory(*buf_addr);
			if (!NT_SUCCESS(error)) {
				return {};
			}
		}
		else {
			thread_handle = ::CreateRemoteThread(Handle(), NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(start_routine), reinterpret_cast<PVOID64>(parameter), dwCreationFlags, &thread_id);
		}
	}
	if (thread_handle == NULL) {
		return {};
	}
	return Thread{ thread_handle };
}

std::optional<uint16_t> Process::BlockThread(Thread* thread) const
{
	if (!thread->Suspend()) {
		return {};
	}
	unsigned char jmpSelf[] = { 0xeb, 0xfe };
	uint64_t ip;
	if (IsX86()) {
		_CONTEXT32 context;
		GetThreadContext(thread, context);
		ip = context.Eip;
	}
	else {
		_CONTEXT64 context;
		GetThreadContext(thread, context);
		ip = context.Rip;
	}
	auto old_instr = LockAddress(ip);
	thread->Resume();
	return old_instr;
}

bool Process::ResumeBlockedThread(Thread* thread, uint16_t instr) const
{
	if (!thread->Suspend()) {
		return false;
	}
	uint16_t oldInstr;
	uint64_t ip;
	if (IsX86()) {
		_CONTEXT32 context;
		GetThreadContext(thread, context);
		ip = context.Eip;
	}
	else {
		_CONTEXT64 context;
		GetThreadContext(thread, context);
		ip = context.Rip;
	}
	auto success = UnlockAddress(ip, instr);
	thread->Resume();
	return success;
}

bool Process::IsTheOwningThread(Thread* thread) const
{
	return GetProcessIdOfThread(thread) == ProcId();
}

bool Process::GetThreadContext(Thread* thread, _CONTEXT32& context, DWORD flags) const
{
	if (IsX86()) {
		return false;
	}
	bool success;
	context.ContextFlags = flags;
	if (!CurIsX86()) {
		success = ::Wow64GetThreadContext(thread->handle(), &context);
	}
	else {
		success = ::GetThreadContext(thread->handle(), reinterpret_cast<CONTEXT*>(&context));
	}
	return success;
}

bool Process::GetThreadContext(Thread* thread, _CONTEXT64& context, DWORD flags) const
{
	if (IsX86()) {
		return false;
	}
	bool success;
	context.ContextFlags = flags;
	if (ms_wow64.Wow64Operation(Handle())) {
		success = ms_wow64.GetThreadContext64(thread->handle(), &context);
	}
	else {
		success = ::GetThreadContext(thread->handle(), reinterpret_cast<CONTEXT*>(&context));
	}
	return success;
}

bool Process::SetThreadContext(Thread* thread, _CONTEXT32& context, DWORD flags) const
{
	if (!IsX86()) {
		return false;
	}
	bool success; 
	context.ContextFlags = flags;
	if (!CurIsX86()) {
		success = ::Wow64SetThreadContext(thread->handle(), &context);
	}
	else {
		success = ::SetThreadContext(thread->handle(), reinterpret_cast<CONTEXT*>(&context));
	}
	return success;
}

bool Process::SetThreadContext(Thread* thread, _CONTEXT64& context, DWORD flags) const
{
	if (!IsX86()) {
		return false;
	}
	bool success;
	context.ContextFlags = flags;
	if (ms_wow64.Wow64Operation(Handle())) {
		success = ms_wow64.SetThreadContext64(thread->handle(), &context);
	}
	else {
		success = ::SetThreadContext(thread->handle(), reinterpret_cast<CONTEXT*>(&context));
	}
	return success;
}

bool Process::WaitExit(DWORD dwMilliseconds) const
{
	if (IsCur()) {
		return false;
	}
	return WaitForSingleObject(Handle(), dwMilliseconds) == WAIT_OBJECT_0;
}

std::optional<DWORD> Process::GetExitCode() const
{
	DWORD code;
	if (!GetExitCodeProcess(Handle(), &code)) {
		return {};
	}
	return code;
}

// std::optional<uint64_t> Process::LoadLibraryFromImage(Image* image, bool exec_tls_callback, bool call_dll_entry,
// 	uint64_t init_parameter, bool skip_not_loaded, bool zero_pe_header, bool entry_call_sync)
// {
// 	if (IsX86() != image->IsPE32()) {
// 		return 0;
// 	}
// 	auto image_base_res = AllocMemory(image->GetImageSize(), (DWORD)MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
// 	if (!image_base_res) return {};
// 	auto& image_base = *image_base_res;
// 	bool success = false;
// 	do {
// 		if (!image->RepairRepositionTable(image_base)) {
// 			break;
// 		}
// 		if (!RepairImportAddressTable(image, skip_not_loaded)) {
// 			break;
// 		}
// 		auto image_buf = image->SaveToImageBuf(image_base, zero_pe_header);
// 		if (!WriteMemory(image_base, image_buf.data(), image_buf.size())) {
// 			break;
// 		}
// 		/*
//             * tls的调用必须同步，否则出现并发执行的问题
//             */
// 		if (exec_tls_callback) {
// 			ExecuteTls(image, image_base);
// 		}
// 		if (call_dll_entry) {
// 			CallEntryPoint(image, image_base, init_parameter, entry_call_sync);
// 		}
// 		success = true;
// 	} while (false);
// 	if (success == false && image_base) {
// 		FreeMemory(image_base);
// 		image_base = 0;
// 	}
// 	image->SetMemoryImageBase(image_base);
// 	return image_base;
// }

std::optional<Image> Process::LoadImageFromImageBase(uint64_t image_base) const
{
	if (IsCur()) {
		return Image::LoadFromImageBuf((void*)image_base, image_base);
	}
	else {
		auto module_info = GetModuleInfoByModuleBase(image_base);
		if (!module_info) return {};
		auto buf = ReadMemory(image_base, module_info.value().size);
		if (!buf) {
			return {};
		}
		return Image::LoadFromImageBuf(buf->data(), image_base);
	}
}

bool Process::FreeLibraryFromImage(Image* image, bool call_dll_entry) const
{
	if (call_dll_entry) {
		//if (!CallEntryPoint(image, image->GetMemoryImageBase(), DLL_PROCESS_DETACH)) {
		//    return false;
		//}
	}
	FreeMemory(image->GetMemoryImageBase());
	return true;
}

bool Process::FreeLibraryFromBase(uint64_t base, bool call_dll_entry)
{
	auto module_info = GetModuleInfoByModuleBase(base);
	if (!module_info) {
		return false;
	}
	auto image = GetImageByModuleInfo(*module_info);
	if (!image) {
		return false;
	}
	return FreeLibraryFromImage(&*image, call_dll_entry);
}

std::optional<uint64_t> Process::LoadLibraryW(std::wstring_view lib_name, bool sync)
{
	if (IsCur()) {
		auto addr = ::LoadLibraryW(lib_name.data());
		if (!addr) {
			return {};
		}
		return reinterpret_cast<uint64_t>(addr);
	}

	auto module = GetModuleInfoByModuleName(lib_name);
	if (module) {
		return module.value().base;
	}

	uint64_t addr = NULL;
        
	if (ms_wow64.Wow64Operation(Handle())) {
		auto ntdll64 = ms_wow64.GetNTDLL64();
		auto LdrLoadDll = ms_wow64.GetProcAddress64(ntdll64, "LdrLoadDll");
		UNICODE_STRING64 us64;
		auto str_len = lib_name.size() * 2;
		if (str_len % 8 != 0) {
			str_len += 8 - str_len % 8;
		}
		auto len = 0x1000 + str_len + sizeof(UNICODE_STRING64) + sizeof(DWORD64);
		auto lib_name_buf_res = AllocMemory(NULL, len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!lib_name_buf_res) {
			return {};
		}
		auto lib_name_buf = *lib_name_buf_res;
		lib_name_buf += 0x1000;
		do {
			if (!WriteMemory(lib_name_buf, lib_name.data(), len)) {
				break;
			}
			auto unicode_str_addr = lib_name_buf + str_len;
               
			auto raw_str_len = lib_name.size() * 2;
			if (!WriteMemory(uint64_t{ unicode_str_addr + reinterpret_cast<uint64_t>(&((UNICODE_STRING64*)0)->Length) }, &raw_str_len, 2)) {
				break;
			}
			if (!WriteMemory(uint64_t{ unicode_str_addr + reinterpret_cast<uint64_t>(&((UNICODE_STRING64*)0)->MaximumLength) }, &raw_str_len, 2)) {
				break;
			}
			if (!WriteMemory(uint64_t{ unicode_str_addr + reinterpret_cast<uint64_t>(&((UNICODE_STRING64*)0)->Buffer) }, &lib_name_buf, 8)) {
				break;
			}

			Call(lib_name_buf - 0x1000, LdrLoadDll, { 0, 0, unicode_str_addr, unicode_str_addr + sizeof(UNICODE_STRING64) }, &addr, Process::CallConvention::kStdCall, sync);
		} while (false);
		if (sync && lib_name_buf) {
			FreeMemory(lib_name_buf);
		}

	}
	else {
		auto len = 0x1000 + lib_name.size() * 2 + 2;
		auto lib_name_buf_res = AllocMemory(NULL, len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!lib_name_buf_res) {
			return {};
		}
		auto lib_name_buf = *lib_name_buf_res;
		lib_name_buf += 0x1000;
		do {
			if (!WriteMemory(lib_name_buf, lib_name.data(), len)) {
				break;
			}
			Call(lib_name_buf - 0x1000, (uint64_t)::LoadLibraryW, { lib_name_buf }, &addr, Process::CallConvention::kStdCall, sync);
		} while (false);
		if (sync && lib_name_buf) {
			FreeMemory(lib_name_buf);
		}
	}
        
	return addr;
}

bool Process::FreeLibrary(uint64_t module_base) const
{
	if (IsCur()) {
		return ::FreeLibrary((HMODULE)module_base);
	}
	do {
		auto thread = CreateThread((uint64_t)::FreeLibrary, module_base);
		if (!thread) {
			return false;
		}
		thread.value().WaitExit(INFINITE);
	} while (false);
	return false;
}

std::optional<Image> Process::GetImageByModuleInfo(const geek::ModuleInfo& info) const
{
	auto buf = ReadMemory(info.base, info.size);
	if (!buf) return {};
	return Image::LoadFromImageBuf(buf->data(), info.base);
}

// std::optional<uint64_t> Process::GetExportProcAddress(Image* image, const char* func_name)
// {
// 	uint32_t export_rva;
// 	if (reinterpret_cast<uintptr_t>(func_name) <= 0xffff) {
// 		export_rva = image->GetExportRvaByOrdinal(reinterpret_cast<uint16_t>(func_name));
// 	}
// 	else {
// 		export_rva = image->GetExportRvaByName(func_name);
// 	}
// 	// 可能返回一个字符串，需要二次加载
// 	// 对应.def文件的EXPORTS后加上 MsgBox = user32.MessageBoxA 的情况
// 	uint64_t va = (uint64_t)image->GetMemoryImageBase() + export_rva;
// 	auto export_directory = (uint64_t)image->GetMemoryImageBase() + image->GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
// 	auto export_directory_size = image->GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
// 	// 还在导出表范围内，是这样子的字符串：NTDLL.RtlAllocateHeap
// 	if (va > export_directory && va < export_directory + export_directory_size) {
// 		std::string full_name = (char*)image->RvaToPoint(export_rva);
// 		auto offset = full_name.find(".");
// 		auto dll_name = full_name.substr(0, offset);
// 		auto func_name = full_name.substr(offset + 1);
// 		if (!dll_name.empty() && !func_name.empty()) {
// 			auto image_base = LoadLibrary(geek::Convert::AnsiToUtf16le(dll_name).c_str());
// 			if (image_base == 0) return {};
// 			auto import_image = LoadImageFromImageBase(image_base.value());
// 			if (!import_image) return {};
// 			auto va_res = GetExportProcAddress(&import_image.value(), func_name.c_str());
// 			if (!va_res) return {};
// 			return va_res.value();
// 		}
// 	}
// 	return va;
// }

bool Process::Call(uint64_t exec_page, uint64_t call_addr, const std::vector<uint64_t>& par_list, uint64_t* ret_value,
	CallConvention call_convention, bool sync, bool init_exec_page)
{

	bool success = false;
	if (IsX86()) {
		if (call_convention == CallConvention::kStdCall) {
			std::vector<uint32_t> converted_values;
			converted_values.reserve(par_list.size());  // 预先分配足够的空间

			// 遍历 input，将每个 uint64_t 值转换为 uint32_t 并存入 result
			std::transform(par_list.begin(), par_list.end(), std::back_inserter(converted_values),
			               [](uint64_t value) {
				               return static_cast<uint32_t>(value);  // 显式转换
			               });

			auto context = CallContextX86{};
			if (par_list.size() > 0) {
				auto list = std::initializer_list<uint32_t>(&*converted_values.begin(), &*(converted_values.end() - 1) + 1);
				context.stack = list;
			}
			success = Call(exec_page, call_addr, &context, sync, init_exec_page);
			if (ret_value && !sync) {
				*ret_value = context.eax;
			}
		}
	}
	else {
		auto context = CallContextAmd64{};
		if (par_list.size() >= 5) {
			auto list = std::initializer_list<uint64_t>(&par_list[4], &*(par_list.end() - 1) + 1);
			context.stack = list;
		}
		if (par_list.size() >= 1) {
			context.rcx = par_list[0];
		}
		if (par_list.size() >= 2) {
			context.rcx = par_list[1];
		}
		if (par_list.size() >= 3) {
			context.r8 = par_list[2];
		}
		if (par_list.size() >= 4) {
			context.r9 = par_list[3];
		}
		success = Call(exec_page, call_addr, &context, sync, init_exec_page);
		if (ret_value && !sync) {
			*ret_value = context.rax;
		}
	}
	return success;
}

bool Process::Call(uint64_t call_addr, const std::vector<uint64_t>& par_list, uint64_t* ret_value,
	CallConvention call_convention)
{
	auto exec_page  = AllocMemory(NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!exec_page) {
		return false;
	}
	bool success = Call(*exec_page, call_addr, par_list, ret_value, call_convention, true, true);
	FreeMemory(*exec_page);
	return success;
}

bool Process::CallGenerateCodeX86(uint64_t exec_page, bool sync) const
{
	constexpr int32_t exec_offset = 0x100;

	std::array<uint8_t, 0x1000> temp_data = { 0 };
	uint8_t* temp = temp_data.data();
	if (IsCur()) {
		temp = reinterpret_cast<uint8_t*>(exec_page);
	}

	int32_t i = exec_offset;

	// 保存非易变寄存器
	// push ebp
	temp[i++] = 0x55;
	// mov ebp, esp
	temp[i++] = 0x89;
	temp[i++] = 0xe5;

	// 3个局部变量
	// sub esp, 0xc
	temp[i++] = 0x83;
	temp[i++] = 0xec;
	temp[i++] = 0x0c;

	// push ebx
	temp[i++] = 0x53;
	// push esi
	temp[i++] = 0x56;
	// push edi
	temp[i++] = 0x57;

	// 获取ExecPageHeaderX86*
	// mov eax, [ebp + 8]
	temp[i++] = 0x8b;
	temp[i++] = 0x45;
	temp[i++] = 0x08;

	// copy stack
	// mov ecx, [ExecPageHeaderX86.stack_count]
	temp[i++] = 0x8b;
	temp[i++] = 0x48;
	temp[i++] = offsetof(ExecPageHeaderX86, stack_count);

	// mov esi, [ExecPageHeaderX86.stack_addr]
	temp[i++] = 0x8b;
	temp[i++] = 0x70;
	temp[i++] = offsetof(ExecPageHeaderX86, stack_addr);

	// mov eax, 4
	temp[i++] = 0xb8;
	*(uint32_t*)&temp[i] = 4;
	i += 4;

	// mul ecx
	temp[i++] = 0xf7;
	temp[i++] = 0xe1;

	// sub esp, eax
	temp[i++] = 0x29;
	temp[i++] = 0xc4;

	// mov edi, esp
	temp[i++] = 0x89;
	temp[i++] = 0xe7;

	// cld
	temp[i++] = 0xfc;

	// rep movsd
	temp[i++] = 0xf3;
	temp[i++] = 0xa5;

	// 获取ExecPageHeaderX86*
	// mov eax, [ebp + 8]
	temp[i++] = 0x8b;
	temp[i++] = 0x45;
	temp[i++] = 0x08;

	// mov ecx, [ExecPageHeaderX86.context_addr]
	temp[i++] = 0x8b;
	temp[i++] = 0x48;
	temp[i++] = offsetof(ExecPageHeaderX86, context_addr);

	// mov eax, [ExecPageHeaderX86.call_addr]
	temp[i++] = 0x36;
	temp[i++] = 0x8b;
	temp[i++] = 0x40;
	temp[i++] = offsetof(ExecPageHeaderX86, call_addr);

	// 调用地址保存到局部变量1
	// mov [ebp - 4], eax
	temp[i++] = 0x89;
	temp[i++] = 0x45;
	temp[i++] = -0x04;

	// mov eax, [context.eax]
	temp[i++] = 0x8b;
	temp[i++] = 0x41;
	temp[i++] = offsetof(CallContextX86, eax);

	// mov edx, [context.edx]
	temp[i++] = 0x8b;
	temp[i++] = 0x51;
	temp[i++] = offsetof(CallContextX86, edx);

	// mov ebx, [context.ebx]
	temp[i++] = 0x8b;
	temp[i++] = 0x59;
	temp[i++] = offsetof(CallContextX86, ebx);

	// mov esi, [context.esi]
	temp[i++] = 0x8b;
	temp[i++] = 0x71;
	temp[i++] = offsetof(CallContextX86, esi);

	// mov edi, [context.edi]
	temp[i++] = 0x8b;
	temp[i++] = 0x79;
	temp[i++] = offsetof(CallContextX86, edi);

	// mov ecx, [context.ecx]
	temp[i++] = 0x8b;
	temp[i++] = 0x49;
	temp[i++] = offsetof(CallContextX86, ecx);

	// call [ebp - 4]
	temp[i++] = 0xff;
	temp[i++] = 0x55;
	temp[i++] = -0x04;

	// 两个寄存器先保存到局部变量
	// mov [ebp - 8], ecx
	temp[i++] = 0x89;
	temp[i++] = 0x4d;
	temp[i++] = -0x08;

	// mov [ebp - 0xc], eax
	temp[i++] = 0x89;
	temp[i++] = 0x45;
	temp[i++] = -0x0c;

	// mov eax, [ebp + 8]
	temp[i++] = 0x8b;
	temp[i++] = 0x45;
	temp[i++] = 0x08;

	// mov ecx, [ExecPageHeaderX86.context_addr]
	temp[i++] = 0x8b;
	temp[i++] = 0x48;
	temp[i++] = offsetof(ExecPageHeaderX86, context_addr);

	// 暂时不做栈拷贝
	// add esp, [context.balanced_esp]
	temp[i++] = 0x03;
	temp[i++] = 0x61;
	temp[i++] = offsetof(CallContextX86, balanced_esp);

	// mov eax, [ebp - 0xc]
	temp[i++] = 0x8b;
	temp[i++] = 0x45;
	temp[i++] = -0x0c;

	// mov [context.eax], eax
	temp[i++] = 0x89;
	temp[i++] = 0x41;
	temp[i++] = offsetof(CallContextX86, eax);

	// mov [context.edx], edx
	temp[i++] = 0x89;
	temp[i++] = 0x51;
	temp[i++] = offsetof(CallContextX86, edx);

	// mov [context.ebx], ebx
	temp[i++] = 0x89;
	temp[i++] = 0x59;
	temp[i++] = offsetof(CallContextX86, ebx);

	// mov [context.esi], esi
	temp[i++] = 0x89;
	temp[i++] = 0x71;
	temp[i++] = offsetof(CallContextX86, esi);

	// mov [context.edi], edi
	temp[i++] = 0x89;
	temp[i++] = 0x79;
	temp[i++] = offsetof(CallContextX86, edi);

	// mov eax(context), ecx
	temp[i++] = 0x89;
	temp[i++] = 0xC8;

	// mov ecx, [ebp - 8]
	temp[i++] = 0x8b;
	temp[i++] = 0x4d;
	temp[i++] = -0x08;

	// mov [context.ecx], ecx
	temp[i++] = 0x89;
	temp[i++] = 0x48;
	temp[i++] = offsetof(CallContextX86, ecx);

	// pop edi
	temp[i++] = 0x5f;
	// pop esi
	temp[i++] = 0x5e;
	// pop ebx
	temp[i++] = 0x5b;

	// mov esp, ebp
	temp[i++] = 0x89;
	temp[i++] = 0xec;

	// pop ebp
	temp[i++] = 0x5d;

	if (sync && IsCur()) {
		temp[i++] = 0xc3;
	}
	else {
		// 创建线程需要平栈
		temp[i++] = 0xc2;        // ret 4
		*(uint16_t*)&temp[i] = 4;
		i += 2;
	}

	if (!IsCur()) {
		if (!WriteMemory(exec_page, temp, 0x1000)) {
			return false;
		}
	}
	return true;
}

bool Process::Call(uint64_t exec_page, uint64_t call_addr, CallContextX86* context, bool sync, bool init_exec_page) const
{
	constexpr int32_t header_offset = 0x0;
	constexpr int32_t context_offset = 0x40;
	constexpr int32_t stack_offset = 0x80; // 0x80 = 128 / 4 = 32个参数

	constexpr int32_t exec_offset = 0x100;

	if (init_exec_page) {
		if (!CallGenerateCodeX86(exec_page, sync)) {
			return false;
		}
	}

	bool success = false;
	do {
		if (sync && IsCur()) {
			ExecPageHeaderX86 header;
			header.call_addr = static_cast<uint32_t>(call_addr);
			header.context_addr = reinterpret_cast<uint32_t>(context);
			header.stack_count = static_cast<uint32_t>(context->stack.size());
			header.stack_addr = reinterpret_cast<uint32_t>(context->stack.begin());
			using Func = void(*)(ExecPageHeaderX86*);
			Func func = reinterpret_cast<Func>(exec_page + exec_offset);
			func(&header);
		}
		else {
			if (!WriteMemory(exec_page + context_offset, context, offsetof(CallContextX86, stack))) {
				return false;
			}
			if (!WriteMemory(exec_page + stack_offset, context->stack.begin(), context->stack.size() * sizeof(uint32_t))) {
				return false;
			}

			ExecPageHeaderX86 header;
			header.call_addr = static_cast<uint32_t>(call_addr);
			header.context_addr = static_cast<uint32_t>(exec_page + context_offset);
			header.stack_count = static_cast<uint32_t>(context->stack.size());
			header.stack_addr = static_cast<uint32_t>(exec_page + stack_offset);
			if (!WriteMemory(exec_page + header_offset, &header, sizeof(header))) {
				return false;
			}

			auto thread = CreateThread(exec_page + exec_offset, exec_page + header_offset);
			if (!thread) {
				break;
			}

			if (sync) {
				if (!thread.value().WaitExit()) {
					break;
				}
				ReadMemory(exec_page + context_offset, context, offsetof(CallContextX86, stack));
			}
		}
		success = true;
	} while (false);
	return success;
}

bool Process::Call(uint64_t call_addr, CallContextX86* context, bool sync) const
{
	uint64_t exec_page = 0;
	bool init_exec_page = true;
	bool success = false;
	if (sync && IsCur()) {
		static CallPageX86 call_page(nullptr, true);
		exec_page = call_page.exec_page();
		if (!exec_page) {
			return false;
		}
		success = Call(exec_page, call_addr, context, sync, false);
	}
	else {
		auto res = AllocMemory(NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (res) {
			exec_page = *res;
			CallGenerateCodeX86(exec_page, sync);
		}
		if (!exec_page) {
			return false;
		}
		success = Call(exec_page, call_addr, context, sync, false);
		if (sync) {
			FreeMemory(exec_page);
		}
	}
	return success;
}

bool Process::CallGenerateCodeAmd64(uint64_t exec_page, bool sync) const
{
	constexpr int32_t exec_offset = 0x800;

	std::array<uint8_t, 0x1000> temp_data = { 0 };
	uint8_t* temp = temp_data.data();
	if (IsCur()) {
		temp = reinterpret_cast<uint8_t*>(exec_page);
	}

	int32_t i = exec_offset;

	// 保存参数
	// mov [rsp+8], rcx // ExecPageHeaderX64*
	//temp[i++] = 0x48;
	//temp[i++] = 0x89;
	//temp[i++] = 0x4c;
	//temp[i++] = 0x24;
	//temp[i++] = 0x08;

	// 保存非易变寄存器
	// push rbx
	temp[i++] = 0x53;

	// push rbp
	temp[i++] = 0x55;

	// push rsi
	temp[i++] = 0x56;

	// push rdi
	temp[i++] = 0x57;

	// push r12
	temp[i++] = 0x41;
	temp[i++] = 0x54;

	// push r13
	temp[i++] = 0x41;
	temp[i++] = 0x55;

	// push r14
	temp[i++] = 0x41;
	temp[i++] = 0x56;

	// push r15
	temp[i++] = 0x41;
	temp[i++] = 0x57;

	// 预分配栈，直接分一块足够大的空间，0x400给参数，0x20给局部变量，0x8是对齐
	// sub rsp, 0x428
	temp[i++] = 0x48;
	temp[i++] = 0x81;
	temp[i++] = 0xec;
	*(uint32_t*)&temp[i] = 0x428;
	i += 4;

	// mov rax, [ExecPageHeaderAmd64.call_addr]
	temp[i++] = 0x48;
	temp[i++] = 0x8b;
	temp[i++] = 0x41;
	temp[i++] = offsetof(ExecPageHeaderAmd64, call_addr);
        
	// 调用地址放到第一个局部变量
	// mov [rsp+0x400], rax
	temp[i++] = 0x48;
	temp[i++] = 0x89;
	temp[i++] = 0x84;
	temp[i++] = 0x24;
	*(uint32_t*)&temp[i] = 0x400;
	i += 4;

	// mov rax, [ExecPageHeaderAmd64.context_addr]
	temp[i++] = 0x48;
	temp[i++] = 0x8b;
	temp[i++] = 0x41;
	temp[i++] = offsetof(ExecPageHeaderAmd64, context_addr);
	// context放到第二个局部变量
        
	// mov [rsp+0x400+0x8], rax
	temp[i++] = 0x48;
	temp[i++] = 0x89;
	temp[i++] = 0x84;
	temp[i++] = 0x24;
	*(uint32_t*)&temp[i] = 0x400 + 0x8;
	i += 4;

	// copy stack
	// mov rsi, [ExecPageHeaderAmd64.stack_addr]
	temp[i++] = 0x48;
	temp[i++] = 0x8b;
	temp[i++] = 0x71;
	temp[i++] = offsetof(ExecPageHeaderAmd64, stack_addr);

	// mov rcx, [ExecPageHeaderAmd64.stack_count]
	temp[i++] = 0x48;
	temp[i++] = 0x8b;
	temp[i++] = 0x49;
	temp[i++] = offsetof(ExecPageHeaderAmd64, stack_count);

	// 从rsp+0x20开始复制
	// mov rdi, rsp
	temp[i++] = 0x48;
	temp[i++] = 0x89;
	temp[i++] = 0xe7;

	// add rdi, 0x20
	temp[i++] = 0x48;
	temp[i++] = 0x83;
	temp[i++] = 0xc7;
	temp[i++] = 0x20;

	// cld
	temp[i++] = 0xfc;

	// rep movsq
	temp[i++] = 0xf3;
	temp[i++] = 0x48;
	temp[i++] = 0xa5;


	// 拿到context_addr
	// mov rcx, [rsp + 0x400 + 0x8]
	temp[i++] = 0x48;
	temp[i++] = 0x8b;
	temp[i++] = 0x8c;
	temp[i++] = 0x24;
	*(uint32_t*)&temp[i] = 0x400 + 0x8;
	i += 4;

	// mov rax, [context.rax]
	temp[i++] = 0x48;
	temp[i++] = 0x8b;
	temp[i++] = 0x41;
	temp[i++] = offsetof(CallContextAmd64, rax);

	// mov rdx, [context.rdx]
	temp[i++] = 0x48;
	temp[i++] = 0x8b;
	temp[i++] = 0x51;
	temp[i++] = offsetof(CallContextAmd64, rdx);

	// mov rbx, [context.rbx]
	temp[i++] = 0x48;
	temp[i++] = 0x8b;
	temp[i++] = 0x59;
	temp[i++] = offsetof(CallContextAmd64, rbx);

	// mov rbp, [context.rbp]
	temp[i++] = 0x48;
	temp[i++] = 0x8b;
	temp[i++] = 0x69;
	temp[i++] = offsetof(CallContextAmd64, rbp);

	// mov rsi, [context.rsi]
	temp[i++] = 0x48;
	temp[i++] = 0x8b;
	temp[i++] = 0x71;
	temp[i++] = offsetof(CallContextAmd64, rsi);

	// mov rdi, [context.rdi]
	temp[i++] = 0x48;
	temp[i++] = 0x8b;
	temp[i++] = 0x79;
	temp[i++] = offsetof(CallContextAmd64, rdi);

	// mov r8, [context.r8]
	temp[i++] = 0x4c;
	temp[i++] = 0x8b;
	temp[i++] = 0x41;
	temp[i++] = offsetof(CallContextAmd64, r8);

	// mov r9, [context.r9]
	temp[i++] = 0x4c;
	temp[i++] = 0x8b;
	temp[i++] = 0x49;
	temp[i++] = offsetof(CallContextAmd64, r9);

	// mov r10, [context.r10]
	temp[i++] = 0x4c;
	temp[i++] = 0x8b;
	temp[i++] = 0x51;
	temp[i++] = offsetof(CallContextAmd64, r10);

	// mov r11, [context.r11]
	temp[i++] = 0x4c;
	temp[i++] = 0x8b;
	temp[i++] = 0x59;
	temp[i++] = offsetof(CallContextAmd64, r11);

	// mov r12, [context.r12]
	temp[i++] = 0x4c;
	temp[i++] = 0x8b;
	temp[i++] = 0x61;
	temp[i++] = offsetof(CallContextAmd64, r12);

	// mov r13, [context.r13]
	temp[i++] = 0x4c;
	temp[i++] = 0x8b;
	temp[i++] = 0x69;
	temp[i++] = offsetof(CallContextAmd64, r13);

	// mov r14, [context.r14]
	temp[i++] = 0x4c;
	temp[i++] = 0x8b;
	temp[i++] = 0x71;
	temp[i++] = offsetof(CallContextAmd64, r14);

	// mov r15, [context.r15]
	temp[i++] = 0x4c;
	temp[i++] = 0x8b;
	temp[i++] = 0x79;
	temp[i++] = offsetof(CallContextAmd64, r15);

	// mov rcx, [context.rcx]
	temp[i++] = 0x48;
	temp[i++] = 0x8b;
	temp[i++] = 0x49;
	temp[i++] = offsetof(CallContextAmd64, rcx);

	// call [rsp + 0x400]
	temp[i++] = 0xff;
	temp[i++] = 0x94;
	temp[i++] = 0x24;
	*(uint32_t*)&temp[i] = 0x400;
	i += 4;
        
	// 局部变量保存下rcx
	// mov [rsp + 0x400 + 0x10], rcx
	temp[i++] = 0x48;
	temp[i++] = 0x89;
	temp[i++] = 0x8c;
	temp[i++] = 0x24;
	*(uint32_t*)&temp[i] = 0x400 + 0x10;
	i += 4;

	// 拿到context_addr
	// mov rcx, [rsp + 0x400 + 0x8]
	temp[i++] = 0x48;
	temp[i++] = 0x8b;
	temp[i++] = 0x8c;
	temp[i++] = 0x24;
	*(uint32_t*)&temp[i] = 0x400 + 0x8;
	i += 4;


	// mov [context.rax], rax
	temp[i++] = 0x48;
	temp[i++] = 0x89;
	temp[i++] = 0x41;
	temp[i++] = offsetof(CallContextAmd64, rax);

	// mov [context.rdx], rdx
	temp[i++] = 0x48;
	temp[i++] = 0x89;
	temp[i++] = 0x51;
	temp[i++] = offsetof(CallContextAmd64, rdx);

	// mov [context.rbx], rbx
	temp[i++] = 0x48;
	temp[i++] = 0x89;
	temp[i++] = 0x59;
	temp[i++] = offsetof(CallContextAmd64, rbx);

	// mov [context.rbp], rbp
	temp[i++] = 0x48;
	temp[i++] = 0x89;
	temp[i++] = 0x69;
	temp[i++] = offsetof(CallContextAmd64, rbp);

	// mov [context.rsi], rsi
	temp[i++] = 0x48;
	temp[i++] = 0x89;
	temp[i++] = 0x71;
	temp[i++] = offsetof(CallContextAmd64, rsi);

	// mov [context.rdi], rdi
	temp[i++] = 0x48;
	temp[i++] = 0x89;
	temp[i++] = 0x79;
	temp[i++] = offsetof(CallContextAmd64, rdi);

	// mov [context.r8], r8
	temp[i++] = 0x4c;
	temp[i++] = 0x89;
	temp[i++] = 0x41;
	temp[i++] = offsetof(CallContextAmd64, r8);

	// mov [context.r9], r9
	temp[i++] = 0x4c;
	temp[i++] = 0x89;
	temp[i++] = 0x49;
	temp[i++] = offsetof(CallContextAmd64, r9);

	// mov [context.r10], r10
	temp[i++] = 0x4c;
	temp[i++] = 0x89;
	temp[i++] = 0x51;
	temp[i++] = offsetof(CallContextAmd64, r10);

	// mov [context.r11], r11
	temp[i++] = 0x4c;
	temp[i++] = 0x89;
	temp[i++] = 0x59;
	temp[i++] = offsetof(CallContextAmd64, r11);

	// mov [context.r12], r12
	temp[i++] = 0x4c;
	temp[i++] = 0x89;
	temp[i++] = 0x61;
	temp[i++] = offsetof(CallContextAmd64, r12);

	// mov [context.r13], r13
	temp[i++] = 0x4c;
	temp[i++] = 0x89;
	temp[i++] = 0x69;
	temp[i++] = offsetof(CallContextAmd64, r13);

	// mov [context.r14], r14
	temp[i++] = 0x4c;
	temp[i++] = 0x89;
	temp[i++] = 0x71;
	temp[i++] = offsetof(CallContextAmd64, r14);

	// mov [context.r15], r15
	temp[i++] = 0x4c;
	temp[i++] = 0x89;
	temp[i++] = 0x79;
	temp[i++] = offsetof(CallContextAmd64, r15);


	// mov rax(context), rcx
	temp[i++] = 0x48;
	temp[i++] = 0x8b;
	temp[i++] = 0xC1;

	// mov rcx, [rsp + 0x400 + 0x10]
	temp[i++] = 0x48;
	temp[i++] = 0x8b;
	temp[i++] = 0x8c;
	temp[i++] = 0x24;
	*(uint32_t*)&temp[i] = 0x400 + 0x10;
	i += 4;

	// mov [context.rcx], rcx
	temp[i++] = 0x48;
	temp[i++] = 0x89;
	temp[i++] = 0x48;
	temp[i++] = offsetof(CallContextAmd64, rcx);


	// add rsp, 0x428
	temp[i++] = 0x48;
	temp[i++] = 0x81;
	temp[i++] = 0xc4;
	*(uint32_t*)&temp[i] = 0x428;
	i += 4;

	// pop r15
	temp[i++] = 0x41;
	temp[i++] = 0x5f;

	// pop r14
	temp[i++] = 0x41;
	temp[i++] = 0x5e;

	// pop r13
	temp[i++] = 0x41;
	temp[i++] = 0x5d;
        
	// pop r12
	temp[i++] = 0x41;
	temp[i++] = 0x5c;

	// pop rdi
	temp[i++] = 0x5f;

	// pop rsi
	temp[i++] = 0x5e;

	// pop rbp
	temp[i++] = 0x5d;

	// pop rbx
	temp[i++] = 0x5b;

	// ret
	temp[i++] = 0xc3;

	if (!IsCur()) {
		if (!WriteMemory(exec_page, temp, 0x1000)) {
			return false;
		}
	}
	return true;
}

bool Process::Call(uint64_t exec_page, uint64_t call_addr, CallContextAmd64* context, bool sync, bool init_exec_page) const
{
	constexpr int32_t header_offset = 0x0;
	constexpr int32_t context_offset = 0x100;
	constexpr int32_t stack_offset = 0x400; // 0x400 = 128 / 8 = 128个参数

	constexpr int32_t exec_offset = 0x800;

	if (init_exec_page) {
		if (!CallGenerateCodeAmd64(exec_page, sync)) {
			return false;
		}
	}

	bool success = false;
	do {
		if (sync && IsCur()) {
			ExecPageHeaderAmd64 header;
			header.call_addr = call_addr;
			header.context_addr = reinterpret_cast<uint64_t>(context);
			header.stack_count = context->stack.size();
			header.stack_addr = reinterpret_cast<uint64_t>(context->stack.begin());
			using Func = void(*)(ExecPageHeaderAmd64*);
			Func func = reinterpret_cast<Func>(exec_page + exec_offset);
			func(&header);
		}
		else {
			if (!WriteMemory(exec_page + context_offset, context, offsetof(CallContextX86, stack))) {
				return false;
			}
			if (!WriteMemory(exec_page + stack_offset, context->stack.begin(), context->stack.size() * sizeof(uint32_t))) {
				return false;
			}

			ExecPageHeaderAmd64 header;
			header.call_addr = call_addr;
			header.context_addr = exec_page + context_offset;
			header.stack_count = context->stack.size();
			header.stack_addr = exec_page + stack_offset;
			if (!WriteMemory(exec_page + header_offset, &header, sizeof(header))) {
				return false;
			}

			auto thread = CreateThread(exec_page + exec_offset, exec_page + header_offset);
			if (!thread) {
				break;
			}

			if (sync) {
				if (!thread.value().WaitExit()) {
					break;
				}
				ReadMemory(exec_page + context_offset, context, offsetof(CallContextAmd64, stack));
			}
		}
		success = true;
	} while (false);
	return success;
}

bool Process::Call(uint64_t call_addr, CallContextAmd64* context, bool sync) const
{
	uint64_t exec_page = 0;
	bool init_exec_page = true;
	bool success = false;
	if (sync && IsCur()) {
		static CallPageAmd64 call_page(nullptr, true);
		exec_page = call_page.exec_page();
		if (!exec_page) {
			return false;
		}
		success = Call(exec_page, call_addr, context, sync, false);
	}
	else {
		auto res = AllocMemory(NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (res) {
			exec_page = *res;
			CallGenerateCodeAmd64(exec_page, sync);
		}
		if (!exec_page) {
			return false;
		}
		success = Call(exec_page, call_addr, context, sync, false);
		if (sync) {
			FreeMemory(exec_page);
		}
	}
	return success;
}

// bool Process::RepairImportAddressTable(Image* image, bool skip_not_loaded)
// {
// 	auto import_descriptor = (_IMAGE_IMPORT_DESCRIPTOR*)image->RvaToPoint(image->GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
// 	if (import_descriptor == nullptr) {
// 		return false;
// 	}
// 	for (; import_descriptor->FirstThunk; import_descriptor++) {
// 		if(import_descriptor->OriginalFirstThunk == NULL) import_descriptor->OriginalFirstThunk = import_descriptor->FirstThunk;
// 		char* import_module_name = (char*)image->RvaToPoint(import_descriptor->Name);
// 		auto import_module_base_res = LoadLibrary(geek::Convert::AnsiToUtf16le(import_module_name).c_str());
// 		if (!import_module_base_res) return false;
// 		if (image->IsPE32()) {
// 			if (!RepairImportAddressTableFromModule<IMAGE_THUNK_DATA32>(*this, image, import_descriptor, import_module_base_res.value(), skip_not_loaded)) {
// 				return false;
// 			}
// 		}
// 		else {
// 			if (!RepairImportAddressTableFromModule<IMAGE_THUNK_DATA64>(*this, image, import_descriptor, import_module_base_res.value(), skip_not_loaded)) {
// 				return false;
// 			}
// 		}
// 	}
// 	return true;
// }
//
// bool Process::ExecuteTls(Image* image, uint64_t image_base)
// {
// 	auto tls_dir = (IMAGE_TLS_DIRECTORY*)image->RvaToPoint(image->GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
// 	if (tls_dir == nullptr) {
// 		return false;
// 	}
// 	PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)tls_dir->AddressOfCallBacks;
// 	if (callback) {
// 		while (true) {
// 			if (IsCur()) {
// 				if (!*callback) {
// 					break;
// 				}
// 				if (image->IsPE32()) {
// 					PIMAGE_TLS_CALLBACK32 callback32 = *(PIMAGE_TLS_CALLBACK32*)callback;
// 					callback32((uint32_t)image_base, DLL_PROCESS_ATTACH, NULL);
// 				}
// 				else {
// 					PIMAGE_TLS_CALLBACK64 callback64 = *(PIMAGE_TLS_CALLBACK64*)callback;
// 					callback64(image_base, DLL_PROCESS_ATTACH, NULL);
// 				}
// 			}
// 			else {
// 				if (image->IsPE32()) {
// 					PIMAGE_TLS_CALLBACK32 callback32;
// 					if (!ReadMemory((uint64_t)callback, &callback32, sizeof(PIMAGE_TLS_CALLBACK32))) {
// 						return false;
// 					}
// 					Call(image_base, (uint64_t)callback32, { image_base, DLL_PROCESS_ATTACH , NULL });
// 				}
// 				else {
// 					PIMAGE_TLS_CALLBACK64 callback64;
// 					if (!ReadMemory((uint64_t)callback, &callback64, sizeof(PIMAGE_TLS_CALLBACK64))) {
// 						return false;
// 					}
// 					Call(image_base, (uint64_t)callback64, { image_base, DLL_PROCESS_ATTACH , NULL });
// 				}
// 			}
// 			callback++;
// 		}
// 	}
// 	return true;
// }

bool Process::CallEntryPoint(Image* image, uint64_t image_base, uint64_t init_parameter, bool sync)
{
	if (IsCur()) {
		uint32_t rva = image->NtHeader().OptionalHeader().AddressOfEntryPoint();
		if (image->IsDll()) {
			if (image->IsPE32()) {
				DllEntryProc32 DllEntry = (DllEntryProc32)(image_base + rva);
				DllEntry((uint32_t)image_base, DLL_PROCESS_ATTACH, (uint32_t)init_parameter);
			}
			else {
				DllEntryProc64 DllEntry = (DllEntryProc64)(image_base + rva);
				DllEntry(image_base, DLL_PROCESS_ATTACH, init_parameter);
			}
		}
		else {
			ExeEntryProc ExeEntry = (ExeEntryProc)(LPVOID)(image_base + rva);
			// exe不执行
		}
	}
	else {
		uint64_t entry_point = (uint64_t)image_base + image->NtHeader().OptionalHeader().AddressOfEntryPoint();
		if (!Call(image_base, entry_point, { image_base, DLL_PROCESS_ATTACH , init_parameter }, nullptr, CallConvention::kStdCall, sync)) {
			return false;
		}
	}
	return true;
}

std::optional<std::vector<ModuleInfo>> Process::GetModuleInfoList() const
{
	/*
        * https://blog.csdn.net/wh445306/article/details/107867375
        */

	std::vector<ModuleInfo> moduleList;
	if (IsX86()) {
		HMODULE NtdllModule = GetModuleHandleW(L"ntdll.dll");
		pfnNtQueryInformationProcess NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(NtdllModule, "NtQueryInformationProcess");

		PROCESS_BASIC_INFORMATION32 pbi32 = { 0 };

		if (!NT_SUCCESS(NtQueryInformationProcess(Handle(), ProcessBasicInformation, &pbi32, sizeof(pbi32), NULL))) {
			return {};
		}

		DWORD Ldr32 = 0;
		LIST_ENTRY32 ListEntry32 = { 0 };
		LDR_DATA_TABLE_ENTRY32 LDTE32 = { 0 };

		if (!ReadMemory((pbi32.PebBaseAddress + offsetof(PEB32, Ldr)), &Ldr32, sizeof(Ldr32))) {
			return {};
		}
		if (!ReadMemory((Ldr32 + offsetof(PEB_LDR_DATA32, InLoadOrderModuleList)), &ListEntry32, sizeof(ListEntry32))) {
			return {};
		}
		if (!ReadMemory((ListEntry32.Flink), &LDTE32, sizeof(LDTE32))) {
			return {};
		}

		while (true) {
			if (LDTE32.InLoadOrderLinks.Flink == ListEntry32.Flink) break;
			std::vector<wchar_t> full_name(LDTE32.FullDllName.Length + 1, 0);
			if (!ReadMemory(LDTE32.FullDllName.Buffer, (wchar_t*)full_name.data(), LDTE32.FullDllName.Length)) {
				continue;
			}
			std::vector<wchar_t> base_name(LDTE32.BaseDllName.Length + 1, 0);
			if (!ReadMemory(LDTE32.BaseDllName.Buffer, (wchar_t*)base_name.data(), LDTE32.BaseDllName.Length)) {
				continue;
			}
			ModuleInfo module(LDTE32, base_name.data(), full_name.data());
			moduleList.push_back(module);
			if (!ReadMemory(LDTE32.InLoadOrderLinks.Flink, &LDTE32, sizeof(LDTE32))) break;
		}
	}
	else {
		HMODULE NtdllModule = GetModuleHandleW(L"ntdll.dll");
		PROCESS_BASIC_INFORMATION64 pbi64 = { 0 };
		if (ms_wow64.Wow64Operation(Handle())) {
			pfnNtWow64QueryInformationProcess64 NtWow64QueryInformationProcess64 = (pfnNtWow64QueryInformationProcess64)GetProcAddress(NtdllModule, "NtWow64QueryInformationProcess64");
			if (!NT_SUCCESS(NtWow64QueryInformationProcess64(Handle(), ProcessBasicInformation, &pbi64, sizeof(pbi64), NULL))) {
				return {};
			}
		}
		else {
			pfnNtQueryInformationProcess NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(NtdllModule, "NtQueryInformationProcess");
			if (!NT_SUCCESS(NtQueryInformationProcess(Handle(), ProcessBasicInformation, &pbi64, sizeof(pbi64), NULL))) {
				return {};
			}
		}

		DWORD64 Ldr64 = 0;
		LIST_ENTRY64 ListEntry64 = { 0 };
		LDR_DATA_TABLE_ENTRY64 LDTE64 = { 0 };
		wchar_t ProPath64[256];

		if (!ReadMemory((pbi64.PebBaseAddress + offsetof(PEB64, Ldr)), &Ldr64, sizeof(Ldr64))) {
			return {};
		}
		if (!ReadMemory((Ldr64 + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList)), &ListEntry64, sizeof(LIST_ENTRY64))) {
			return {};
		}
		if (!ReadMemory((ListEntry64.Flink), &LDTE64, sizeof(LDTE64))) {
			return {};
		}

		while (true) {
			if (LDTE64.InLoadOrderLinks.Flink == ListEntry64.Flink) break;
			std::vector<wchar_t> full_name(LDTE64.FullDllName.Length + 1, 0);
			if (!ReadMemory(LDTE64.FullDllName.Buffer, (wchar_t*)full_name.data(), LDTE64.FullDllName.Length)) {
				if (!ReadMemory(LDTE64.InLoadOrderLinks.Flink, &LDTE64, sizeof(LDTE64))) break;
				continue;
			}
			std::vector<wchar_t> base_name(LDTE64.BaseDllName.Length + 1, 0);
			if (!ReadMemory(LDTE64.BaseDllName.Buffer, (wchar_t*)base_name.data(), LDTE64.BaseDllName.Length)) {
				if (!ReadMemory(LDTE64.InLoadOrderLinks.Flink, &LDTE64, sizeof(LDTE64))) break;
				continue;
			}
			ModuleInfo module(LDTE64, base_name.data(), full_name.data());
			moduleList.push_back(module);
			if (!ReadMemory(LDTE64.InLoadOrderLinks.Flink, &LDTE64, sizeof(LDTE64))) break;
		}

	}
	return moduleList;
}

std::optional<ModuleInfo> Process::GetModuleInfoByModuleName(std::wstring_view name) const
{
	std::wstring find_name = geek::Convert::ToUppercase(name.data());
	if (find_name == L"NTDLL") find_name += L".DLL";
	auto module_list_res = GetModuleInfoList();
	if (!module_list_res) return {};
	for (auto& it : module_list_res.value()) {
		auto base_name_up = geek::Convert::ToUppercase(it.base_name);
		if (base_name_up == find_name) {
			return it;
		}
	}
	return {};
}

std::optional<ModuleInfo> Process::GetModuleInfoByModuleBase(uint64_t base) const
{
	auto module_list = GetModuleInfoList();
	if (!module_list)return {};
	for (auto& it : module_list.value()) {
		if (it.base == base) {
			return it;
		}
	}
	return {};
}

std::optional<std::vector<uint8_t>> Process::GetResource(HMODULE hModule, DWORD ResourceID, LPCWSTR type)
{
	bool success = false;
	std::vector<uint8_t> res;
	HRSRC hResID = NULL;
	HRSRC hRes = NULL;
	HANDLE hResFile = INVALID_HANDLE_VALUE;
	do {
		HRSRC hResID = FindResourceW(hModule, MAKEINTRESOURCEW(ResourceID), type);
		if (!hResID) {
			break;
		}

		HGLOBAL hRes = LoadResource(hModule, hResID);
		if (!hRes) {
			break;
		}

		LPVOID pRes = LockResource(hRes);
		if (pRes == NULL) {
			break;
		}

		unsigned long dwResSize = SizeofResource(hModule, hResID);
		res.resize(dwResSize);
		memcpy(&res[0], pRes, dwResSize);
		success = true;
	} while (false);

	if (hResFile != INVALID_HANDLE_VALUE) {
            
		hResFile = INVALID_HANDLE_VALUE;
	}
	if (hRes) {
		UnlockResource(hRes);
		FreeResource(hRes);
		hRes = NULL;
	}
	if (!success) {
		return {};
	}
	return res;
}

bool Process::SaveFileFromResource(HMODULE hModule, DWORD ResourceID, LPCWSTR type, LPCWSTR saveFilePath)
{
	auto resource = GetResource(hModule, ResourceID, type);
	if (!resource) {
		return false;
	}
	return geek::File::WriteFile(saveFilePath, resource->data(), resource->size());
}

Process::Process(UniqueHandle process_handle) noexcept:
	process_handle_ { std::move(process_handle) }
{
}

bool Process::CurIsX86()
{
	Process process{ kCurrentProcess };
	return process.IsX86();
}

DWORD Process::GetProcessIdFromThread(Thread* thread)
{
	return ::GetProcessIdOfThread(thread->handle());
}

std::optional<std::vector<ProcessInfo>> Process::GetProcessInfoList()
{
	PROCESSENTRY32W pe32 = { 0 };
	pe32.dwSize = sizeof(PROCESSENTRY32W);
	std::vector<ProcessInfo> processEntryList;

	UniqueHandle hProcessSnap{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL) };
	if (!Process32FirstW(*hProcessSnap, &pe32)) {
		return {};
	}
	do {
		processEntryList.push_back(ProcessInfo(pe32));
	} while (Process32NextW(*hProcessSnap, &pe32));
	return processEntryList;
}

std::optional<std::map<DWORD, ProcessInfo>> Process::GetProcessIdMap()
{
	PROCESSENTRY32W pe32 = { 0 };
	pe32.dwSize = sizeof(PROCESSENTRY32W);
	std::map<DWORD, ProcessInfo> process_map;

	UniqueHandle hProcessSnap{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL) };
	if (!Process32FirstW(*hProcessSnap, &pe32)) {
		return {};
	}
	do {
		process_map.insert(std::make_pair(pe32.th32ProcessID, ProcessInfo(pe32)));
	} while (Process32NextW(*hProcessSnap, &pe32));
	return process_map;
}

std::optional<std::wstring> Process::GetProcessNameByProcessId(DWORD pid, std::vector<ProcessInfo>* cache)
{
	std::vector<ProcessInfo>* process_list = cache;
	std::vector<ProcessInfo> copy;
	if (process_list == nullptr) {
		auto copy_res = GetProcessInfoList();
		if (!copy_res) return {};
		copy = std::move(*copy_res);
		process_list = &copy;
	}
	for (auto& process : *process_list) {
		if (pid == process.process_id) {
			return std::wstring(process.process_name);
		}
	}
	return {};
}

std::optional<DWORD> Process::GetProcessIdByProcessName(std::wstring_view processName, size_t count)
{
	auto process_entry_list = GetProcessInfoList();
	if (!process_entry_list) return {};

	std::wstring processName_copy = processName.data();
	int i = 0;
	for (auto& entry : process_entry_list.value()) {
		auto exeFile_str = geek::Convert::ToUppercase(entry.process_name);
		processName_copy = geek::Convert::ToUppercase(processName_copy);
		if (exeFile_str == processName_copy) {
			if (++i < count) {
				continue;
			}
			return entry.process_id;
		}
	}
	return {};
}

bool Process::Terminate(std::wstring_view processName)
{
	auto process = Open(processName);
	if (!process) return false;
	return process.value().Terminate(0);
}
}
