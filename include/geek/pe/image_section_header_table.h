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
	 * ��ȡ��������
	 */
	std::string_view Name() const;

	/**
	 * ��ȡ��������
	 */
	const std::vector<uint8_t>& RawData() const;
	/**
	 * ��ȡ��������
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
	 * ����������ȡ����
	 */
	std::optional<ImageSectionHeader> GetHeaderByIndex(size_t index) const;
	/**
	 * �������ƻ�ȡ����
	 * @param name ע���ַ�����������<=8������Ļ�ض�
	 */
	std::optional<ImageSectionHeader> GetHeaderByName(std::string_view name) const;

	ImageSectionHeader operator[](size_t index) const;
	ImageSectionHeader operator[](std::string_view name) const;

private:
	friend class ImageSectionHeader;
	Image* image_;
};
}
