#pragma once
#include <optional>
#include <string_view>
#include <vector>
#include <Windows.h>

namespace geek {
class Image;
class ImageSectionHeaderTable;

class ImageSectionHeader
{
public:
	ImageSectionHeader(
		ImageSectionHeaderTable* owner_table,
		size_t section_index,
		IMAGE_SECTION_HEADER* raw_header,
		std::vector<uint8_t>* raw_data);

	/**
	 * 获取区段名称
	 */
	std::string_view Name() const;

	/**
	 * 获取区段数据
	 */
	const std::vector<uint8_t>& RawData() const;
	/**
	 * 获取区段数据
	 */
	std::vector<uint8_t>& RawData();

private:
	ImageSectionHeaderTable* owner_table_;
	size_t section_index_;
	IMAGE_SECTION_HEADER* raw_;
	std::vector<uint8_t>* raw_data_;
};

class ImageSectionHeaderTable
{
public:
	ImageSectionHeaderTable(Image* image);

	/**
	 * 根据索引获取区段
	 */
	std::optional<ImageSectionHeader> GetHeaderByIndex(size_t index) const;
	/**
	 * 根据名称获取区段
	 * @param name 注意字符串数量必须<=8，多出的会截断
	 */
	std::optional<ImageSectionHeader> GetHeaderByName(std::string_view name) const;

	ImageSectionHeader operator[](size_t index) const;
	ImageSectionHeader operator[](std::string_view name) const;

private:
	friend class ImageSectionHeader;
	Image* image_;
};
}
