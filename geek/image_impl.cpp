#include "image_impl.h"

namespace geek {
Image::Impl::Impl(Image* owner)
	: owner_(owner)
{
}

bool Image::Impl::CopyPEHeader(void* buf_, IMAGE_SECTION_HEADER** sectionHeaderTable)
{
	auto buf = (char*)buf_;
	dos_header_ = *(IMAGE_DOS_HEADER*)buf;
	if (dos_header_.e_magic != 'ZM') {        // 'MZ'
		return false;
	}
	auto dosStubSize = dos_header_.e_lfanew - sizeof(dos_header_);
	if (dosStubSize < 0) {
		dosStubSize = 0;
	}
	dos_stub_.resize(dosStubSize, 0);
	memcpy(dos_stub_.data(), &buf[sizeof(dos_header_)], dosStubSize);

	auto ntHeader = (IMAGE_NT_HEADERS32*)&buf[dos_header_.e_lfanew];
	if (ntHeader->Signature != 'EP') {        // 'PE'
		return false;
	}

	// 拷贝PE头
	auto optionalHeader32 = &ntHeader->OptionalHeader;
	if (optionalHeader32->Magic == 0x10b) {
		nt_header_ = new IMAGE_NT_HEADERS32;
		*nt_header_ = *ntHeader;
	}
	else if (optionalHeader32->Magic == 0x20b) {
		nt_header_ = (IMAGE_NT_HEADERS32*)new IMAGE_NT_HEADERS64;
		*(IMAGE_NT_HEADERS64*)nt_header_ = *(IMAGE_NT_HEADERS64*)ntHeader;
	}
	else {
		return false;
	}

	file_header_ = &nt_header_->FileHeader;

	auto optionalHeader = &nt_header_->OptionalHeader;
	if (optionalHeader->Magic == 0x10b) {
		*sectionHeaderTable = (IMAGE_SECTION_HEADER*)(ntHeader + 1);
	}
	else {
		*sectionHeaderTable = (IMAGE_SECTION_HEADER*)((IMAGE_NT_HEADERS64*)ntHeader + 1);
	}
	return true;
}

uint32_t Image::Impl::NarrowAlignment(uint32_t val, uint32_t alignval) noexcept
{
	return val - val % alignval;
}

uint32_t Image::Impl::ExpandedAlignment(uint32_t val, uint32_t alignval) noexcept
{
	return val - val % alignval + alignval;
}

void* Image::Impl::RvaToPoint(uint32_t rva)
{
	auto i = GetSectionIndexByRva(rva);
	if (i == -1) {
		return nullptr;
	}
	return &section_list_[i][rva - section_header_table_[i].VirtualAddress];
}

int Image::Impl::GetSectionIndexByRva(uint32_t rva) const
{
	int i = 0;
	for (; i < file_header_->NumberOfSections; i++) {
		if (rva < section_header_table_[i].VirtualAddress) {
			return i - 1;
		}
	}

	i--;
	// 可能位于最后一个节区，但不能越界
	if (rva - section_header_table_[i].VirtualAddress > section_header_table_[i].SizeOfRawData) {
		return -1;
	}

	return i;
}

int Image::Impl::GetSectionIndexByRAW(uint32_t raw) const
{
	int i = 0;
	for (; i < file_header_->NumberOfSections; i++) {
		if (raw < section_header_table_[i].PointerToRawData) {
			return i - 1;
		}
	}

	i--;
	// 可能位于最后一个节区，但不能越界
	if (raw - section_header_table_[i].PointerToRawData + 1 > section_header_table_[i].SizeOfRawData) {
		return -1;
	}

	return i;
}

uint32_t Image::Impl::PointToRaw(void* point)
{
	for (int i = 0; i < file_header_->NumberOfSections; i++) {
		auto addr = &section_list_[i][0];
		if ((uint8_t*)point >= addr && (uint8_t*)point < &section_list_[i][section_list_[i].size() - 1]) {
			return section_header_table_[i].VirtualAddress + ((uintptr_t)point - (uintptr_t)section_list_[i].data());
		}
	}
	return 0;
}

uint32_t Image::Impl::RvaToRaw(uint32_t rva) const
{
	auto i = GetSectionIndexByRva(rva);
	if (i == -1) {
		return 0;
	}
	return rva - section_header_table_[i].VirtualAddress + section_header_table_[i].PointerToRawData;
}

uint32_t Image::Impl::RawToRva(uint32_t raw) const
{
	auto i = GetSectionIndexByRAW(raw);
	if (i == -1) {
		return 0;
	}
	return raw - section_header_table_[i].PointerToRawData + section_header_table_[i].VirtualAddress;
}

uint32_t Image::Impl::calc_checksum(uint32_t checksum, const void* data, int length)
{
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

uint32_t Image::Impl::generate_pe_checksum(const void* file_base, uint32_t file_size) const
{
	uint32_t file_checksum = 0;
	if (nt_header_) {
		file_checksum = calc_checksum(0, file_base, file_size >> 1);
		if (file_size & 1) {
			file_checksum += (uint16_t) * ((char*)file_base + file_size - 1);
		}
	}
	return (file_size + file_checksum);
}
}
