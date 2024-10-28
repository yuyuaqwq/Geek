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
	ImageBaseRelocationList(Image* owner_image);

	ImageBaseRelocationListNode begin() const;
	ImageBaseRelocationListNode end() const;
	size_t size() const;

private:
	size_t size_;
	IMAGE_BASE_RELOCATION* begin_raw_;
	IMAGE_BASE_RELOCATION* end_raw_;
	Image* owner_image_;
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

	uint32_t VirtualAddress() const;
	uint32_t SizeOfBlock() const;

	bool IsEnd() const;

protected:
	IMAGE_BASE_RELOCATION* raw_;
	const ImageBaseRelocationList* owner_;
};

class ImageBaseRelocationFieldList
{
public:
	ImageBaseRelocationFieldList(ImageBaseRelocationListNode* owner, IMAGE_BASE_RELOCATION* raw_reloc);


private:
	IMAGE_BASE_RELOCATION* raw_reloc_;
};
}
