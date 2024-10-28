#include <cassert>
#include <geek/pe/data_directory/image_base_relocation.h>
#include <geek/pe/image.h>

namespace geek {
ImageBaseRelocationList::ImageBaseRelocationList(Image* owner_image)
	: owner_image_(owner_image)
{
	auto& dir = owner_image_->NtHeader().OptionalHeader().DataDirectory().raw()[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	begin_raw_ = reinterpret_cast<IMAGE_BASE_RELOCATION*>(owner_image_->RvaToPoint(dir.VirtualAddress));
	end_raw_ = begin_raw_;
	size_ = 0;
	while (end_raw_->VirtualAddress != 0)
	{
		assert(size_ < 256);
		end_raw_ = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<char*>(begin_raw_) + begin_raw_->SizeOfBlock);
		++size_;
	}
}

ImageBaseRelocationListNode ImageBaseRelocationList::begin() const
{
	return { const_cast<ImageBaseRelocationList*>(this), begin_raw_ };
}

ImageBaseRelocationListNode ImageBaseRelocationList::end() const
{
	return { const_cast<ImageBaseRelocationList*>(this), end_raw_ };
}

size_t ImageBaseRelocationList::size() const
{
	return size_;
}

bool ImageBaseRelocationListNode::IsEnd() const
{
	return SizeOfBlock() == 0 || VirtualAddress() == 0;
}


ImageBaseRelocationListNode::ImageBaseRelocationListNode(ImageBaseRelocationList* owner, IMAGE_BASE_RELOCATION* raw)
	: raw_(raw), owner_(owner)
{
}

ImageBaseRelocationFieldList ImageBaseRelocationListNode::Fields() const
{
	return { const_cast<ImageBaseRelocationListNode*>(this), raw_ };
}

ImageBaseRelocationListNode& ImageBaseRelocationListNode::operator++()
{
	auto next = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<char*>(raw_) + SizeOfBlock());
	raw_ = next;
	return *this;
}

ImageBaseRelocationListNode ImageBaseRelocationListNode::operator++(int)
{
	auto tmp = *this;
	++*this;
	return tmp;
}

uint32_t ImageBaseRelocationListNode::VirtualAddress() const
{
	return raw()->VirtualAddress;
}

uint32_t ImageBaseRelocationListNode::SizeOfBlock() const
{
	return raw()->SizeOfBlock;
}
}
