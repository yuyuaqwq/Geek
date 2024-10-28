#include <cassert>

#include <geek/pe/image_section_header_table.h>

#include "image_impl.h"

namespace geek {
ImageSectionHeader::ImageSectionHeader(ImageSectionHeaderTable* owner_table, size_t section_index, IMAGE_SECTION_HEADER* raw_header, std::vector<uint8_t>* raw_data)
	: owner_table_(owner_table),
	section_index_(section_index),
	raw_(raw_header),
	raw_data_(raw_data)
{
}

std::string_view ImageSectionHeader::Name() const
{
	return reinterpret_cast<const char*>(raw_->Name);
}

const std::vector<uint8_t>& ImageSectionHeader::RawData() const
{
	return *raw_data_;
}

std::vector<uint8_t>& ImageSectionHeader::RawData()
{
	return *raw_data_;
}

ImageSectionHeaderTable::ImageSectionHeaderTable(Image* owner_image)
	: owner_image_(owner_image)
{
}

std::optional<ImageSectionHeader> ImageSectionHeaderTable::GetHeaderByIndex(size_t index) const
{
	if (index < owner_image_->impl_->section_header_table_.size())
	{
		return ImageSectionHeader{
			const_cast<ImageSectionHeaderTable*>(this),
			index,
			&owner_image_->impl_->section_header_table_[index],
			&owner_image_->impl_->section_list_[index] };
	}
	return std::nullopt;
}

std::optional<ImageSectionHeader> ImageSectionHeaderTable::GetHeaderByName(std::string_view name) const
{
	name = name.substr(0, IMAGE_SIZEOF_SHORT_NAME);

	size_t i = 0;
	for (auto& s : owner_image_->impl_->section_header_table_)
	{
		// »∑±£0Ω·Œ≤
		char n[IMAGE_SIZEOF_SHORT_NAME + 1]{};
		strcpy_s(n, reinterpret_cast<char const*>(s.Name));

		if (n == name)
		{
			return GetHeaderByIndex(i);
		}
		++i;
	}
	return std::nullopt;
}

ImageSectionHeader ImageSectionHeaderTable::operator[](size_t index) const
{
	if (auto opt = GetHeaderByIndex(index))
	{
		return *opt;
	}
	throw std::invalid_argument("Index out of range");
}

ImageSectionHeader ImageSectionHeaderTable::operator[](std::string_view name) const
{
	if (auto opt = GetHeaderByName(name))
	{
		return *opt;
	}
	throw std::invalid_argument("Section not found");
}
}
