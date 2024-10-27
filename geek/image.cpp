#include "image_impl.h"

#define GET_OPTIONAL_HEADER_FIELD(field, var) \
    { if (impl_->nt_header_->OptionalHeader.Magic == 0x10b) var = impl_->nt_header_->OptionalHeader.##field; \
    else /* (impl_->m_nt_header->OptionalHeader.Magic == 0x20b)*/ var = ((IMAGE_NT_HEADERS64*)impl_->nt_header_)->OptionalHeader.##field; } 
#define SET_OPTIONAL_HEADER_FIELD(field, var) \
    { if (impl_->nt_header_->OptionalHeader.Magic == 0x10b) impl_->nt_header_->OptionalHeader.##field = var; \
    else/* (impl_->m_nt_header->OptionalHeader.Magic == 0x20b)*/ ((IMAGE_NT_HEADERS64*)impl_->nt_header_)->OptionalHeader.##field = var; } 

namespace geek {
Image::~Image()
{
	if (impl_->nt_header_) {
		if (impl_->nt_header_->OptionalHeader.Magic == 0x10b) {
			delete impl_->nt_header_;
		}
		else {
			delete (IMAGE_NT_HEADERS64*)impl_->nt_header_;
		}
	}
}

Image::Image()
{
}

Image::Image(Image&& other) noexcept
{
	operator=(std::move(other));
}

Image& Image::operator=(Image&& other) noexcept
{
	impl_->dos_header_ = other.impl_->dos_header_;
	impl_->dos_stub_ = std::move(other.impl_->dos_stub_);
	impl_->file_header_ = other.impl_->file_header_;
	other.impl_->file_header_ = nullptr;
	impl_->memory_image_base_ = other.impl_->memory_image_base_;
	impl_->nt_header_ = other.impl_->nt_header_; other.impl_->nt_header_ = nullptr;
	impl_->section_header_table_ = std::move(other.impl_->section_header_table_);
	impl_->section_list_ = std::move(other.impl_->section_list_);
	return *this;
}

std::optional<Image> Image::LoadFromImageBuf(void* buf, uint64_t memory_image_base)
{
	Image temp;
	if (!temp.ReloadFromImageBuf(buf, memory_image_base)) {
		return {};
	}
	return temp;
}

std::optional<Image> Image::LoadFromFileBuf(void* buf, uint64_t memory_image_base)
{
	Image temp;
	if (!temp.ReloadFromFileBuf(buf, memory_image_base)) {
		return {};
	}
	return temp;
}

std::optional<Image> Image::LoadFromFile(std::wstring_view path)
{
	Image temp;
	if (!temp.ReloadFromFile(path)) {
		return {};
	}
	return temp;
}

bool Image::ReloadFromImageBuf(void* buf_, uint64_t memory_image_base)
{
	IMAGE_SECTION_HEADER* sectionHeaderTable;
	if (!impl_->CopyPEHeader(buf_, &sectionHeaderTable)) {
		return false;
	}
	auto buf = (char*)buf_;
	impl_->memory_image_base_ = memory_image_base;
	impl_->section_header_table_.resize(impl_->file_header_->NumberOfSections);
	impl_->section_list_.resize(impl_->file_header_->NumberOfSections);

	// 保存节区和头节区
	for (int i = 0; i < impl_->file_header_->NumberOfSections; i++) {
		impl_->section_header_table_[i] = sectionHeaderTable[i];
		auto virtual_size = std::max(impl_->section_header_table_[i].Misc.VirtualSize, impl_->section_header_table_[i].SizeOfRawData);
		uint32_t SectionAlignment;
		GET_OPTIONAL_HEADER_FIELD(SectionAlignment, SectionAlignment);

		// 对齐不一定表示后面就有
		/*if (virtual_size % SectionAlignment) {
                virtual_size += SectionAlignment - virtual_size % SectionAlignment;
            }*/
		impl_->section_list_[i].resize(virtual_size, 0);
		memcpy(impl_->section_list_[i].data(), &buf[impl_->section_header_table_[i].VirtualAddress], virtual_size);
	}
	return true;
}

bool Image::ReloadFromFileBuf(void* buf_, uint64_t memory_image_base)
{
	IMAGE_SECTION_HEADER* sectionHeaderTable;
	if (!impl_->CopyPEHeader(buf_, &sectionHeaderTable)) {
		return false;
	}
	auto buf = (char*)buf_;
	impl_->memory_image_base_ = memory_image_base;
	impl_->section_header_table_.resize(impl_->file_header_->NumberOfSections);
	impl_->section_list_.resize(impl_->file_header_->NumberOfSections);

	// 保存节区和头节区
	for (int i = 0; i < impl_->file_header_->NumberOfSections; i++) {
		impl_->section_header_table_[i] = sectionHeaderTable[i];
		auto virtual_size = std::max(impl_->section_header_table_[i].Misc.VirtualSize, impl_->section_header_table_[i].SizeOfRawData);
		uint32_t SectionAlignment;
		GET_OPTIONAL_HEADER_FIELD(SectionAlignment, SectionAlignment);
		if (virtual_size % SectionAlignment) {
			virtual_size += SectionAlignment - virtual_size % SectionAlignment;
		}

		if (virtual_size == 0) {
			// dll中没有数据的区段？
			GET_OPTIONAL_HEADER_FIELD(SectionAlignment, virtual_size);
			impl_->section_list_[i].resize(virtual_size, 0);
		}
		else {
			impl_->section_list_[i].resize(virtual_size, 0);
			memcpy(impl_->section_list_[i].data(), &buf[impl_->section_header_table_[i].PointerToRawData], impl_->section_header_table_[i].SizeOfRawData);
		}
	}
	impl_->memory_image_base_ = NULL;
	return true;
}

bool Image::ReloadFromFile(std::wstring_view path)
{
	auto pe = File::Open(path, std::ios::in | std::ios::binary);
	if (!pe) {
		return false;
	}
	auto buf = pe.value().Read();
	return ReloadFromFileBuf(buf.data(), 0);
}

bool Image::SaveToFile(std::wstring_view path)
{
	auto pe = File::Open(path, std::ios::out | std::ios::binary | std::ios::trunc);
	if (!pe) {
		return false;
	}
	auto buf = SaveToFileBuf();
	return pe.value().Write(buf);
}

std::vector<uint8_t> Image::SaveToFileBuf()
{
	std::vector<uint8_t> buf(GetFileSize(), 0);
	int offset = 0;

	memcpy(&buf[offset], &impl_->dos_header_, sizeof(impl_->dos_header_));
	offset += sizeof(impl_->dos_header_);

	memcpy(&buf[offset], impl_->dos_stub_.data(), impl_->dos_stub_.size());
	offset += impl_->dos_stub_.size();

	offset = impl_->dos_header_.e_lfanew;

	if (impl_->nt_header_->OptionalHeader.Magic == 0x10b) {
		memcpy(&buf[offset], impl_->nt_header_, sizeof(*impl_->nt_header_));
		offset += sizeof(*impl_->nt_header_);
	}
	else {
		memcpy(&buf[offset], impl_->nt_header_, sizeof(IMAGE_NT_HEADERS64));
		offset += sizeof(IMAGE_NT_HEADERS64);
	}

	for (int i = 0; i < impl_->file_header_->NumberOfSections; i++) {
		memcpy(&buf[offset], &impl_->section_header_table_[i], sizeof(impl_->section_header_table_[i]));
		offset += sizeof(impl_->section_header_table_[i]);
	}

	for (int i = 0; i < impl_->file_header_->NumberOfSections; i++) {
		memcpy(&buf[impl_->section_header_table_[i].PointerToRawData], impl_->section_list_[i].data(), impl_->section_header_table_[i].SizeOfRawData);
	}
	return buf;
}

void Image::SaveToImageBuf(uint8_t* save_buf, uint64_t image_base, bool zero_pe_header)
{
	int offset = 0;
	if (zero_pe_header) {
		if (impl_->section_header_table_.size() > 0) {
			memset(&save_buf[0], 0, impl_->section_header_table_[0].VirtualAddress - 1);
		}
	}
	else{
		memcpy(&save_buf[offset], &impl_->dos_header_, sizeof(impl_->dos_header_));
		offset += sizeof(impl_->dos_header_);

		memcpy(&save_buf[offset], impl_->dos_stub_.data(), impl_->dos_stub_.size());
		offset += impl_->dos_stub_.size();

		offset = impl_->dos_header_.e_lfanew;
		if (image_base == 0) {
			image_base = (uint64_t)save_buf;
		}
		uint64_t old_image_base = GetImageBase();
		SetImageBase(image_base);
		if (impl_->nt_header_->OptionalHeader.Magic == 0x10b) {
			memcpy(&save_buf[offset], impl_->nt_header_, sizeof(*impl_->nt_header_));
			offset += sizeof(*impl_->nt_header_);
		}
		else {
			memcpy(&save_buf[offset], impl_->nt_header_, sizeof(IMAGE_NT_HEADERS64));
			offset += sizeof(IMAGE_NT_HEADERS64);
		}
		SetImageBase(old_image_base);

		for (int i = 0; i < impl_->file_header_->NumberOfSections; i++) {
			memcpy(&save_buf[offset], &impl_->section_header_table_[i], sizeof(impl_->section_header_table_[i]));
			offset += sizeof(impl_->section_header_table_[i]);
		}
	}
	for (int i = 0; i < impl_->file_header_->NumberOfSections; i++) {
		memcpy(&save_buf[impl_->section_header_table_[i].VirtualAddress], impl_->section_list_[i].data(), impl_->section_header_table_[i].SizeOfRawData);
	}
}

std::vector<uint8_t> Image::SaveToImageBuf(uint64_t image_base, bool zero_pe_header)
{
	std::vector<uint8_t> buf(GetImageSize(), 0);
	SaveToImageBuf(buf.data(), image_base, zero_pe_header);
	return buf;
}

bool Image::IsPE32() const
{
	return impl_->nt_header_->OptionalHeader.Magic == 0x10b;
}

bool Image::IsDll() const
{
	return impl_->file_header_->Characteristics == IMAGE_FILE_DLL;
}

uint32_t Image::GetFileSize() const
{
	int sum = GetPEHeaderSize();
	for (int i = 0; i < impl_->file_header_->NumberOfSections; i++) {
		sum += impl_->section_header_table_[i].SizeOfRawData;
	}
	return sum;
}

uint32_t Image::GetImageSize() const
{
	uint32_t headerSize;
	GET_OPTIONAL_HEADER_FIELD(SizeOfImage, headerSize);
	return headerSize;
}

uint32_t Image::GetPEHeaderSize() const
{
	uint32_t headerSize;
	GET_OPTIONAL_HEADER_FIELD(SizeOfHeaders, headerSize);
	return headerSize;
}

uint64_t Image::GetImageBase() const
{
	uint64_t imageBase;
	GET_OPTIONAL_HEADER_FIELD(ImageBase, imageBase);
	return imageBase;
}

uint64_t Image::GetMemoryImageBase() const
{
	return impl_->memory_image_base_;
}

void Image::SetMemoryImageBase(uint64_t imageBase)
{
	impl_->memory_image_base_ = imageBase;
}

void Image::SetImageBase(uint64_t imageBase) const
{
	SET_OPTIONAL_HEADER_FIELD(ImageBase, imageBase);
}

uint32_t Image::GetEntryPoint() const
{
	uint32_t entry_point;
	GET_OPTIONAL_HEADER_FIELD(AddressOfEntryPoint, entry_point);
	return entry_point;
}

void Image::SetEntryPoint(uint32_t entry_point) const
{
	SET_OPTIONAL_HEADER_FIELD(AddressOfEntryPoint, entry_point);
}

IMAGE_DATA_DIRECTORY* Image::GetDataDirectory() const
{
	IMAGE_DATA_DIRECTORY* dataDirectory;
	GET_OPTIONAL_HEADER_FIELD(DataDirectory, dataDirectory);
	return dataDirectory;
}

void* Image::RvaToPoint(uint32_t rva) const
{
	return impl_->RvaToPoint(rva);
}

bool Image::RepairRepositionTable(uint64_t newImageBase)
{
	auto relocationTable = (IMAGE_BASE_RELOCATION*)RvaToPoint(GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	if (relocationTable == nullptr) {
		return false;
	}
	auto imageBase = GetImageBase();
	do {
		auto blockRva = relocationTable->VirtualAddress;
		auto blockSize = relocationTable->SizeOfBlock;
		if (blockRva == 0 && blockSize == 0) {
			break;
		}
		uint16_t* fieldTable = (uint16_t*)((char*)relocationTable + sizeof(*relocationTable));
		relocationTable    = (IMAGE_BASE_RELOCATION*)((char*)relocationTable + blockSize);
		auto fieldCount = (blockSize - sizeof(*relocationTable)) / sizeof(*fieldTable);
		for (int i = 0; i < fieldCount; i++) {
			auto offsetType = fieldTable[i] >> 12;
			if (offsetType == IMAGE_REL_BASED_ABSOLUTE) {
				continue;
			}
			auto Rva = blockRva + (fieldTable[i] & 0xfff);
			if (offsetType == IMAGE_REL_BASED_HIGHLOW) {
				auto addr = (uint32_t*)RvaToPoint(Rva);
				*addr = *addr - imageBase + newImageBase;
			}
			else if (offsetType == IMAGE_REL_BASED_DIR64) {
				auto addr = (uint64_t*)RvaToPoint(Rva);
				*addr = *addr - imageBase + newImageBase;
			}
		}
	} while (true);
	SetImageBase(newImageBase);
	return true;
}

uint32_t Image::GetExportRvaByName(const std::string& func_name)
{
	auto exportDirectory = (IMAGE_EXPORT_DIRECTORY*)RvaToPoint(GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if (exportDirectory == nullptr) {
		return 0;
	}
	auto numberOfNames = exportDirectory->NumberOfNames;
	auto addressOfNames = (uint32_t*)RvaToPoint(exportDirectory->AddressOfNames);
	auto addressOfNameOrdinals = (uint16_t*)RvaToPoint(exportDirectory->AddressOfNameOrdinals);
	auto addressOfFunctions = (uint32_t*)RvaToPoint(exportDirectory->AddressOfFunctions);
	int funcIdx = -1;
	for (int i = 0; i < numberOfNames; i++) {
		auto exportName = (char*)RvaToPoint(addressOfNames[i]);
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

uint32_t Image::GetExportRvaByOrdinal(uint16_t ordinal)
{
	auto exportDirectory = (IMAGE_EXPORT_DIRECTORY*)RvaToPoint(GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if (exportDirectory == nullptr) {
		return 0;
	}
	auto addressOfFunctions = (uint32_t*)RvaToPoint(exportDirectory->AddressOfFunctions);
	// 外部提供的ordinal需要减去base
	auto funcIdx = ordinal - exportDirectory->Base;
	return addressOfFunctions[funcIdx];
}

std::optional<uint32_t> Image::GetImportAddressRawByName(const std::string& lib_name, const std::string& func_name)
{
	//if (!impl_->m_memory_image_base) return {};
	auto import_descriptor = (_IMAGE_IMPORT_DESCRIPTOR*)RvaToPoint(GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	for (; import_descriptor->OriginalFirstThunk && import_descriptor->FirstThunk; import_descriptor++) {
		const char* import_module_name = (char*)RvaToPoint(import_descriptor->Name);
		if (lib_name != import_module_name) {
			continue;
		}
		if (IsPE32()) {
			return impl_->GetImportAddressRawByNameFromDll<IMAGE_THUNK_DATA32>(import_descriptor, func_name);
		}
		else {
			return impl_->GetImportAddressRawByNameFromDll<IMAGE_THUNK_DATA64>(import_descriptor, func_name);
		}
	}
}

std::optional<uint32_t> Image::GetImportAddressRawByAddr(void* address)
{
	//if (!impl_->m_memory_image_base) return nullptr;
	auto import_descriptor = (_IMAGE_IMPORT_DESCRIPTOR*)RvaToPoint(GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	for (; import_descriptor->OriginalFirstThunk && import_descriptor->FirstThunk; import_descriptor++) {
		if (IsPE32()) {
			auto raw = impl_->GetImportAddressRawByAddressFromDll<IMAGE_THUNK_DATA32>(import_descriptor, address);
			if (raw) {
				return raw;
			}
		}
		else {
			auto raw = impl_->GetImportAddressRawByAddressFromDll<IMAGE_THUNK_DATA64>(import_descriptor, address);
			if (raw) {
				return raw;
			}
		}
	}
	return {};
}

bool Image::CheckSum()
{
	uint32_t old_check_sum;
	GET_OPTIONAL_HEADER_FIELD(CheckSum, old_check_sum);
	SET_OPTIONAL_HEADER_FIELD(CheckSum, 0);
	auto buf = SaveToFileBuf();
	uint32_t check_sum = impl_->generate_pe_checksum(buf.data(), buf.size());
	SET_OPTIONAL_HEADER_FIELD(CheckSum, old_check_sum);

	return old_check_sum == check_sum;
}

void Image::RepairCheckSum()
{
	// https://blog.csdn.net/iiprogram/article/details/1585940/
	SET_OPTIONAL_HEADER_FIELD(CheckSum, 0);
	auto buf = SaveToFileBuf();
	uint32_t check_sum = impl_->generate_pe_checksum(buf.data(), buf.size());
	SET_OPTIONAL_HEADER_FIELD(CheckSum, check_sum);
}

std::optional<std::vector<uint8_t>> Image::GetResource(HMODULE handle_module, DWORD resource_id, LPCWSTR type)
{
	// 查找资源
	std::vector<uint8_t> buf;
	HGLOBAL hRes = NULL;
	LPVOID pRes = NULL;
	do {
		HRSRC hResID = FindResourceW(handle_module, MAKEINTRESOURCEW(resource_id), type);
		if (!hResID) {
			return {};
		}
		// 加载资源
		hRes = LoadResource(handle_module, hResID);
		if (!hRes) {
			break;
		}
		// 锁定资源
		pRes = LockResource(hRes);
		if (pRes == NULL) {
			break;
		}
		DWORD dwResSize = SizeofResource(handle_module, hResID);
		buf.resize(dwResSize);
		memcpy(buf.data(), pRes, dwResSize);
	} while (false);

	if (hRes) {
		UnlockResource(hRes);
		FreeResource(hRes);
	}
	if (buf.empty()) return {};
	return buf;
}
}
