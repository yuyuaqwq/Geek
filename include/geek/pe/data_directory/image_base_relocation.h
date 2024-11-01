#pragma once
#include <cstdint>
#include <iterator>
#include <Windows.h>

namespace geek {
class Image;
class ImageBaseRelocationListNode;

class ImageBaseRelocationList
{
public:
	ImageBaseRelocationList(Image* image);

	ImageBaseRelocationListNode begin() const;
	ImageBaseRelocationListNode end() const;
	size_t size() const;

	bool IsValid() const;

private:
	friend class ImageBaseRelocationListNode;
	size_t size_;
	IMAGE_BASE_RELOCATION* begin_raw_;
	IMAGE_BASE_RELOCATION* end_raw_;
	Image* image_;
};


class ImageBaseRelocationFieldList;
class ImageBaseRelocationListNode
{
public:
	using iterator_category = std::forward_iterator_tag;

	ImageBaseRelocationListNode(ImageBaseRelocationList* owner, IMAGE_BASE_RELOCATION* raw);

	const IMAGE_BASE_RELOCATION* raw() const { return raw_; }
	IMAGE_BASE_RELOCATION* raw() { return raw_; }

	ImageBaseRelocationFieldList Fields() const;

	ImageBaseRelocationListNode& operator++();
	ImageBaseRelocationListNode operator++(int);
	bool operator==(const ImageBaseRelocationListNode& right) const;
	bool operator!=(const ImageBaseRelocationListNode& right) const;
	ImageBaseRelocationListNode& operator*();

	uint32_t VirtualAddress() const;
	uint32_t SizeOfBlock() const;

	bool IsEnd() const;

private:
	ImageBaseRelocationList* owner_;
	IMAGE_BASE_RELOCATION* raw_;
};

class ImageBaseRelocationFieldListNode;
class ImageBaseRelocationFieldList
{
public:
	ImageBaseRelocationFieldList(Image* image, IMAGE_BASE_RELOCATION* raw);

	const IMAGE_BASE_RELOCATION* raw() const { return raw_; }
	IMAGE_BASE_RELOCATION* raw() { return raw_; }

	uint16_t* RawFields() const;
	size_t size() const;
	ImageBaseRelocationFieldListNode begin() const;
	ImageBaseRelocationFieldListNode end() const;

private:
	friend class ImageBaseRelocationFieldListNode;
	Image* image_;
	IMAGE_BASE_RELOCATION* raw_;
};

enum class RelBasedType
{
	kAbsolute,	// 无需重定位，用作填充项。当 Type 为 0 时，加载器会跳过该条目
	kHighLow,	// 用于32位地址重定位（常用于 32 位应用程序）。加载器会将地址直接调整到新基址
	kDir64		// 适用于64位绝对地址重定位（常用于 64 位应用程序），加载器会直接调整地址至新基址
};

class ImageBaseRelocationFieldListNode
{
public:
	using iterator_category = std::random_access_iterator_tag;

	ImageBaseRelocationFieldListNode(ImageBaseRelocationFieldList* owner, uint16_t* raw);

	RelBasedType Type() const;
	uint16_t Offset() const;
	uint32_t Rva() const;

	const uint32_t* ResolveAddress32() const;
	const uint64_t* ResolveAddress64() const;

	uint32_t* ResolveAddress32();
	uint64_t* ResolveAddress64();

	ImageBaseRelocationFieldListNode& operator++();
	ImageBaseRelocationFieldListNode operator++(int);
	ImageBaseRelocationFieldListNode& operator--();
	ImageBaseRelocationFieldListNode operator--(int);

	bool operator==(const ImageBaseRelocationFieldListNode& right) const;
	bool operator!=(const ImageBaseRelocationFieldListNode& right) const;
	ImageBaseRelocationFieldListNode& operator*();
	ImageBaseRelocationFieldListNode& operator[](size_t index);

private:
	ImageBaseRelocationFieldList* owner_;
	uint16_t* raw_;
};
}
