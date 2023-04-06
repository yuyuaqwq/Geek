#ifndef GEEK_PE_IMAGE_H_
#define GEEK_PE_IMAGE_H_

#include <string>
#include <vector>

#ifndef WINNT
#include <Windows.h>
#else
#include <ntimage.h>
#endif

#include <Geek/File/file.hpp>

namespace Geek {



#define GET_OPTIONAL_HEADER_FIELD(field, var) \
	{ if (m_nt_header->OptionalHeader.Magic == 0x10b) var = m_nt_header->OptionalHeader.##field; \
	else if (m_nt_header->OptionalHeader.Magic == 0x20b) var = ((IMAGE_NT_HEADERS64*)m_nt_header)->OptionalHeader.##field; } 
#define SET_OPTIONAL_HEADER_FIELD(field, var) \
	{ if (m_nt_header->OptionalHeader.Magic == 0x10b) m_nt_header->OptionalHeader.##field = var; \
	else if (m_nt_header->OptionalHeader.Magic == 0x20b) ((IMAGE_NT_HEADERS64*)m_nt_header)->OptionalHeader.##field = var; } 

class Image {
public:
	Image() : m_dos_header{ 0 }, m_nt_header { nullptr }, m_file_header{ nullptr } {

	}

	~Image() {
		if (m_nt_header) {
			if (m_nt_header->OptionalHeader.Magic == 0x10b) {
				delete m_nt_header;
			}
			else {
				delete (IMAGE_NT_HEADERS64*)m_nt_header;
			}
		}
		
	}


public:
	bool LoadFromImage(void* buf_) {
		IMAGE_SECTION_HEADER* sectionHeaderTable;
		if (!CopyPEHeader(buf_, &sectionHeaderTable)) {
			return false;
		}
		auto buf = (char*)buf_;
		m_section_header_table.resize(m_file_header->NumberOfSections);
		m_section_list.resize(m_file_header->NumberOfSections);
		// 保存节区和头节区
		for (int i = 0; i < m_file_header->NumberOfSections; i++) {
			m_section_header_table[i] = sectionHeaderTable[i];
			m_section_list[i].resize(m_section_header_table[i].SizeOfRawData, 0);
			memcpy(m_section_list[i].data(), &buf[m_section_header_table[i].VirtualAddress], m_section_header_table[i].SizeOfRawData);
		}
		return true;
	}

	bool LoadFromFile(const std::wstring& path) {
		File pe(path, std::ios::in | std::ios::binary);
		if (!pe.Ok()) {
			return false;
		}
		auto buf = pe.Read();
		IMAGE_SECTION_HEADER* sectionHeaderTable;
		if (!CopyPEHeader(buf.data(), &sectionHeaderTable)) {
			return false;
		}
		m_section_header_table.resize(m_file_header->NumberOfSections);
		m_section_list.resize(m_file_header->NumberOfSections);
		// 保存节区和头节区
		for (int i = 0; i < m_file_header->NumberOfSections; i++) {
			m_section_header_table[i] = sectionHeaderTable[i];
			m_section_list[i].resize(m_section_header_table[i].SizeOfRawData, 0);
			memcpy(m_section_list[i].data(), &buf[m_section_header_table[i].PointerToRawData], m_section_header_table[i].SizeOfRawData);
		}
		return true;
	}

	bool SaveToFile(const std::wstring& path) {
		File pe(path, std::ios::out | std::ios::binary | std::ios::trunc);
		if (!pe.Ok()) {
			return false;
		}

		auto buf = SaveToFileBuf();

		return pe.Write(buf);
	}

	std::vector<char> SaveToFileBuf() {
		std::vector<char> buf(GetFileSize(), 0);
		int offset = 0;

		memcpy(&buf[offset], &m_dos_header, sizeof(m_dos_header));
		offset += sizeof(m_dos_header);

		memcpy(&buf[offset], m_dos_stub.data(), m_dos_stub.size());
		offset += m_dos_stub.size();

		offset = m_dos_header.e_lfanew;

		if (m_nt_header->OptionalHeader.Magic == 0x10b) {
			memcpy(&buf[offset], m_nt_header, sizeof(*m_nt_header));
			offset += sizeof(*m_nt_header);
		}
		else {
			memcpy(&buf[offset], m_nt_header, sizeof(IMAGE_NT_HEADERS64));
			offset += sizeof(IMAGE_NT_HEADERS64);
		}

		for (int i = 0; i < m_file_header->NumberOfSections; i++) {
			memcpy(&buf[offset], &m_section_header_table[i], sizeof(m_section_header_table[i]));
			offset += sizeof(m_section_header_table[i]);
		}

		for (int i = 0; i < m_file_header->NumberOfSections; i++) {
			memcpy(&buf[m_section_header_table[i].PointerToRawData], m_section_list[i].data(), m_section_header_table[i].SizeOfRawData);
		}
		return buf;
	}

	uint32_t GetFileSize() {
		int sum = GetPEHeaderSize();
		for (int i = 0; i < m_file_header->NumberOfSections; i++) {
			sum += m_section_header_table[i].SizeOfRawData;
		}
		return sum;
	}

	uint32_t GetImageSize() {
		uint32_t headerSize;
		GET_OPTIONAL_HEADER_FIELD(SizeOfImage, headerSize);
		return headerSize;
	}

	uint32_t GetPEHeaderSize() {
		uint32_t headerSize;
		GET_OPTIONAL_HEADER_FIELD(SizeOfHeaders, headerSize);
		return headerSize;
	}

	uint64_t GetImageBase() {
		uint64_t imageBase;
		GET_OPTIONAL_HEADER_FIELD(ImageBase, imageBase);
		return imageBase;
	}

	void SetImageBase(uint64_t imageBase) {
		SET_OPTIONAL_HEADER_FIELD(ImageBase, imageBase);
	}

	uint32_t GetEntryPoint() {
		uint32_t entry_point;
		GET_OPTIONAL_HEADER_FIELD(AddressOfEntryPoint, entry_point);
		return entry_point;
	}

	void SetEntryPoint(uint32_t entry_point) {
		SET_OPTIONAL_HEADER_FIELD(AddressOfEntryPoint, entry_point);
	}

	IMAGE_DATA_DIRECTORY* GetDataDirectory() {
		IMAGE_DATA_DIRECTORY* dataDirectory;
		GET_OPTIONAL_HEADER_FIELD(DataDirectory, dataDirectory);
		return dataDirectory;
	}

	void* RVAToPoint(uint32_t rva) {
		auto i = GetSectionIndexByRVA(rva);
		if (i == -1) {
			return nullptr;
		}
		return &m_section_list[i][rva - m_section_header_table[i].VirtualAddress];
	}

	uint32_t GetExportRVAByName(const std::string& func_name) {
		auto exportDirectory = (IMAGE_EXPORT_DIRECTORY*)RVAToPoint(GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		if (exportDirectory == nullptr) {
			return 0;
		}
		auto numberOfNames = exportDirectory->NumberOfNames;
		auto addressOfNames = (uint32_t*)RVAToPoint(exportDirectory->AddressOfNames);
		auto addressOfNameOrdinals = (uint16_t*)RVAToPoint(exportDirectory->AddressOfNameOrdinals);
		auto addressOfFunctions = (uint32_t*)RVAToPoint(exportDirectory->AddressOfFunctions);
		int funcIdx = -1;
		for (int i = 0; i < numberOfNames; i++) {
			auto exportName = (char*)RVAToPoint(addressOfNames[i]);
			if (func_name == exportName) {
				// 通过此下标访问序号表，得到访问AddressOfFunctions的下标
				funcIdx = addressOfNameOrdinals[i];
			}
		}
		if (funcIdx == -1) {
			return 0;
		}
		return addressOfFunctions[funcIdx];
	}

	uint32_t GetExportRVAByOrdinal(uint16_t ordinal) {
		auto exportDirectory = (IMAGE_EXPORT_DIRECTORY*)RVAToPoint(GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		if (exportDirectory == nullptr) {
			return 0;
		}
		auto addressOfFunctions = (uint32_t*)RVAToPoint(exportDirectory->AddressOfFunctions);
		// 外部提供的ordinal需要减去base
		auto funcIdx = ordinal - exportDirectory->Base;
		return addressOfFunctions[funcIdx];
	}

	bool RepairRepositionTable(uint64_t newImageBase) {
		auto relocationTable = (IMAGE_BASE_RELOCATION*)RVAToPoint(GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		if (relocationTable == nullptr) {
			return false;
		}
		auto imageBase = GetImageBase();
		do {
			auto blockRVA = relocationTable->VirtualAddress;
			auto blockSize = relocationTable->SizeOfBlock;
			if (blockRVA == 0 && blockSize == 0) {
				break;
			}
			uint16_t* fieldTable = (uint16_t*)((char*)relocationTable + sizeof(*relocationTable));
			relocationTable  = (IMAGE_BASE_RELOCATION*)((char*)relocationTable + blockSize);
			auto fieldCount = (blockSize - sizeof(*relocationTable)) / sizeof(*fieldTable);
			for (int i = 0; i < fieldCount; i++) {
				auto offsetType = fieldTable[i] >> 12;
				if (offsetType == IMAGE_REL_BASED_ABSOLUTE) {
					continue;
				}
				auto RVA = blockRVA + (fieldTable[i] & 0xfff);
				if (offsetType == IMAGE_REL_BASED_HIGHLOW) {
					auto addr = (uint32_t*)RVAToPoint(RVA);
					*addr = *addr - imageBase + newImageBase;
				}
				if (offsetType == IMAGE_REL_BASED_DIR64) {
					auto addr = (uint64_t*)RVAToPoint(RVA);
					*addr = *addr - imageBase + newImageBase;
				}
			}
		} while (true);
		SetImageBase(newImageBase);
		return true;
	}

	bool RepairImportAddressTable() {
		auto import_table = (IMAGE_BASE_RELOCATION*)RVAToPoint(GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		if (import_table == nullptr) {
			return false;
		}
		IMAGE_IMPORT_DESCRIPTOR* import_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)RVAToPoint(import_table->VirtualAddress);
		for (; import_descriptor->OriginalFirstThunk && import_descriptor->FirstThunk; import_descriptor++) {
			char* import_module_name = (char*)RVAToPoint(import_descriptor->Name);
			uint64_t import_module_base = (uint64_t)LoadLibraryA(import_module_name);
			if (import_module_base) {
				continue;
			}
			IMAGE_THUNK_DATA* import_name_table = (IMAGE_THUNK_DATA*)RVAToPoint(import_descriptor->OriginalFirstThunk);
			IMAGE_THUNK_DATA* import_address_table = (IMAGE_THUNK_DATA*)RVAToPoint(import_descriptor->FirstThunk);
			Image import_module;
			import_module.LoadFromImage((void*)import_module_base);
			for (; import_name_table->u1.ForwarderString; import_name_table++, import_address_table++) {
				uint32_t export_rva;
				if (import_name_table->u1.Ordinal >> 31 == 1) {
					export_rva = import_module.GetExportRVAByOrdinal(import_name_table->u1.Ordinal);
				}
				else {
					IMAGE_IMPORT_BY_NAME* func_name = (IMAGE_IMPORT_BY_NAME*)RVAToPoint(import_name_table->u1.AddressOfData);
					export_rva = import_module.GetExportRVAByName((char*)func_name->Name);
				}
				import_address_table->u1.Function = import_module_base + export_rva;
			}
		}
	}

private:
	// https://www.likecs.com/show-306676949.html
	uint32_t calc_checksum(uint32_t checksum, const void* data, int length) {
		if (length && data != nullptr) {
			uint32_t sum = 0;
			do {
				sum = *(uint16_t*)data + checksum;
				checksum = (uint16_t)sum + (sum >> 16);
				data = (char*)data + 2;
			} while (--length);
		}
		return checksum + (checksum >> 16);
	}
	uint32_t generate_pe_checksum(const void* file_base, uint32_t file_size) {
		uint32_t file_checksum = 0;
		if (m_nt_header) {
			file_checksum = calc_checksum(0, file_base, file_size >> 1);
			if (file_size & 1) {
				file_checksum += (uint16_t) * ((char*)file_base + file_size - 1);
			}
		}
		return (file_size + file_checksum);
	}
public:
	bool CheckSum() {
		uint32_t old_check_sum;
		GET_OPTIONAL_HEADER_FIELD(CheckSum, old_check_sum);
		SET_OPTIONAL_HEADER_FIELD(CheckSum, 0);
		auto buf = SaveToFileBuf();
		uint32_t check_sum = generate_pe_checksum(buf.data(), buf.size());
		SET_OPTIONAL_HEADER_FIELD(CheckSum, old_check_sum);

		return old_check_sum == check_sum;
	}

	void RepairCheckSum() {
		// https://blog.csdn.net/iiprogram/article/details/1585940/
		SET_OPTIONAL_HEADER_FIELD(CheckSum, 0);
		auto buf = SaveToFileBuf();
		uint32_t check_sum = generate_pe_checksum(buf.data(), buf.size());
		SET_OPTIONAL_HEADER_FIELD(CheckSum, check_sum);
	}

	bool CheckDigitalSignature() {

	}


private:

	bool CopyPEHeader(void* buf_, IMAGE_SECTION_HEADER** sectionHeaderTable) {
		auto buf = (char*)buf_;
		m_dos_header = *(IMAGE_DOS_HEADER*)buf;
		if (m_dos_header.e_magic != 'ZM') {		// 'MZ'
			return false;
		}
		auto dosStubSize = m_dos_header.e_lfanew - sizeof(m_dos_header);
		if (dosStubSize < 0) {
			dosStubSize = 0;
		}
		m_dos_stub.resize(dosStubSize, 0);
		memcpy(m_dos_stub.data(), &buf[sizeof(m_dos_header)], dosStubSize);

		auto ntHeader = (IMAGE_NT_HEADERS32*)&buf[m_dos_header.e_lfanew];
		if (ntHeader->Signature != 'EP') {		// 'PE'
			return false;
		}

		// 拷贝PE头
		auto optionalHeader32 = &ntHeader->OptionalHeader;
		if (optionalHeader32->Magic == 0x10b) {
			m_nt_header = new IMAGE_NT_HEADERS32;
			*m_nt_header = *ntHeader;
		}
		else if (optionalHeader32->Magic == 0x20b) {
			m_nt_header = (IMAGE_NT_HEADERS32*)new IMAGE_NT_HEADERS64;
			*(IMAGE_NT_HEADERS64*)m_nt_header = *(IMAGE_NT_HEADERS64*)ntHeader;
		}
		else {
			return false;
		}

		m_file_header = &m_nt_header->FileHeader;

		auto optionalHeader = &m_nt_header->OptionalHeader;
		if (optionalHeader->Magic == 0x10b) {
			*sectionHeaderTable = (IMAGE_SECTION_HEADER*)(ntHeader + 1);
		}
		else {
			*sectionHeaderTable = (IMAGE_SECTION_HEADER*)((IMAGE_NT_HEADERS64*)ntHeader + 1);
		}
		return true;
	}

	inline uint32_t NarrowAlignment(uint32_t val, uint32_t alignval) noexcept {
		return val - val % alignval;
	}

	inline uint32_t ExpandedAlignment(uint32_t val, uint32_t alignval) noexcept {
		return val - val % alignval + alignval;
	}

	int GetSectionIndexByRVA(uint32_t rva) {
		int i = 0;
		for (; i < m_file_header->NumberOfSections; i++) {
			if (rva < m_section_header_table[i].VirtualAddress) {
				return i - 1;
			}
		}

		i--;
		// 可能位于最后一个节区，但不能越界
		if (rva - m_section_header_table[i].VirtualAddress > m_section_header_table[i].SizeOfRawData) {
			return -1;
		}

		return i;
	}

	int GetSectionIndexByRAW(uint32_t raw) {
		int i = 0;
		for (; i < m_file_header->NumberOfSections; i++) {
			if (raw < m_section_header_table[i].PointerToRawData) {
				return i - 1;
			}
		}

		i--;
		// 可能位于最后一个节区，但不能越界
		if (raw - m_section_header_table[i].PointerToRawData + 1 > m_section_header_table[i].SizeOfRawData) {
			return -1;
		}

		return i;
	}

	uint32_t RVAToRAW(uint32_t rva) {
		auto i = GetSectionIndexByRVA(rva);
		if (i == -1) {
			return 0;
		}
		return rva - m_section_header_table[i].VirtualAddress + m_section_header_table[i].PointerToRawData;
	}

	uint32_t RAWToRVA(uint32_t raw) {
		auto i = GetSectionIndexByRAW(raw);
		if (i == -1) {
			return 0;
		}
		return raw - m_section_header_table[i].PointerToRawData + m_section_header_table[i].VirtualAddress;
	}


	std::vector<uint8_t> CalculationAuthHashCalc() {

	}


private:
	IMAGE_DOS_HEADER m_dos_header;
	std::vector<uint8_t> m_dos_stub;
	IMAGE_NT_HEADERS32* m_nt_header;
	IMAGE_FILE_HEADER* m_file_header;
	std::vector<IMAGE_SECTION_HEADER> m_section_header_table;
	std::vector<std::vector<uint8_t>> m_section_list;
};

} // namespace Geek

#endif // GEEK_PE_IMAGE_H_