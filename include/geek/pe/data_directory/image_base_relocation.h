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
	kAbsolute,	// �����ض�λ������������ Type Ϊ 0 ʱ������������������Ŀ
	kHighLow,	// ����32λ��ַ�ض�λ�������� 32 λӦ�ó��򣩡��������Ὣ��ֱַ�ӵ������»�ַ
	kDir64		// ������64λ���Ե�ַ�ض�λ�������� 64 λӦ�ó��򣩣���������ֱ�ӵ�����ַ���»�ַ
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
