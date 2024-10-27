#pragma once
#include <geek/pe/image.h>

#undef min
#undef max


namespace geek {
class Image::Impl
{
public:
	Impl(Image* owner);

	bool CopyPEHeader(void* buf_, IMAGE_SECTION_HEADER** sectionHeaderTable);

	static inline uint32_t NarrowAlignment(uint32_t val, uint32_t alignval) noexcept;

	static inline uint32_t ExpandedAlignment(uint32_t val, uint32_t alignval) noexcept;

	void* RvaToPoint(uint32_t rva);

	int GetSectionIndexByRva(uint32_t rva) const;

	int GetSectionIndexByRAW(uint32_t raw) const;

	uint32_t PointToRaw(void* point);

	uint32_t RvaToRaw(uint32_t rva) const;

	uint32_t RawToRva(uint32_t raw) const;

	// https://www.likecs.com/show-306676949.html
	static uint32_t calc_checksum(uint32_t checksum, const void* data, int length);

	uint32_t generate_pe_checksum(const void* file_base, uint32_t file_size) const;

	template<typename IMAGE_THUNK_DATA_T>
	std::optional<uint32_t> GetImportAddressRawByNameFromDll(_IMAGE_IMPORT_DESCRIPTOR* import_descriptor, const std::string& func_name);

	template<typename IMAGE_THUNK_DATA_T>
	std::optional<uint32_t> GetImportAddressRawByAddressFromDll(_IMAGE_IMPORT_DESCRIPTOR* import_descriptor, void* address);

	Image* owner_;
	IMAGE_DOS_HEADER dos_header_{};
	std::vector<uint8_t> dos_stub_;
	IMAGE_NT_HEADERS32* nt_header_ = nullptr;
	IMAGE_FILE_HEADER* file_header_ = nullptr;
	std::vector<IMAGE_SECTION_HEADER> section_header_table_;
	std::vector<std::vector<uint8_t>> section_list_;

	uint64_t memory_image_base_ = 0;
};

template <typename IMAGE_THUNK_DATA_T>
std::optional<uint32_t> Image::Impl::GetImportAddressRawByNameFromDll(_IMAGE_IMPORT_DESCRIPTOR* import_descriptor,
	const std::string& func_name)
{
	IMAGE_THUNK_DATA_T* import_name_table = (IMAGE_THUNK_DATA_T*)RvaToPoint(import_descriptor->OriginalFirstThunk);
	IMAGE_THUNK_DATA_T* import_address_table = (IMAGE_THUNK_DATA_T*)RvaToPoint(import_descriptor->FirstThunk);
	for (; import_name_table->u1.ForwarderString; import_name_table++, import_address_table++) {
		if (import_name_table->u1.Ordinal >> (sizeof(import_name_table->u1.Ordinal) * 8 - 1) == 1) {
			continue;
		}
		else {
			IMAGE_IMPORT_BY_NAME* cur_func_name = (IMAGE_IMPORT_BY_NAME*)RvaToPoint(import_name_table->u1.AddressOfData);
			if (func_name == cur_func_name->Name) {
				auto raw = PointToRaw(&import_address_table->u1.Function);
				if (raw == 0) return {};
				return raw;
			}
		}
	}
	return {};
}

template <typename IMAGE_THUNK_DATA_T>
std::optional<uint32_t> Image::Impl::GetImportAddressRawByAddressFromDll(_IMAGE_IMPORT_DESCRIPTOR* import_descriptor,
	void* address)
{
	IMAGE_THUNK_DATA_T* import_name_table = (IMAGE_THUNK_DATA_T*)RvaToPoint(import_descriptor->OriginalFirstThunk);
	IMAGE_THUNK_DATA_T* import_address_table = (IMAGE_THUNK_DATA_T*)RvaToPoint(import_descriptor->FirstThunk);
	for (; import_name_table->u1.Function; import_name_table++, import_address_table++) {
		if ((void*)import_address_table->u1.Function == address) {
			auto raw = PointToRaw(&import_address_table->u1.Function);
			if (raw == 0) return {};
			return raw;
		}
	}
	return {};
}
}
