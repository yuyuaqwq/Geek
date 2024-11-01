#include <cassert>
#include <geek/pe/data_directory/image_base_relocation.h>
#include <geek/pe/image.h>

namespace geek {
ImageBaseRelocationList::ImageBaseRelocationList(Image* image)
	: image_(image)
{
	auto& dir = image_->NtHeader().OptionalHeader().DataDirectory().raw()[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	begin_raw_ = reinterpret_cast<IMAGE_BASE_RELOCATION*>(image_->RvaToPoint(dir.VirtualAddress));
	end_raw_ = begin_raw_;
	size_ = 0;
	if (begin_raw_ == nullptr)
	{
		return;
	}

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

bool ImageBaseRelocationList::IsValid() const
{
	return begin_raw_ != nullptr && end_raw_ != nullptr && size_ != 0;
}

bool ImageBaseRelocationListNode::IsEnd() const
{
	return SizeOfBlock() == 0 || VirtualAddress() == 0;
}

ImageBaseRelocationListNode::ImageBaseRelocationListNode(ImageBaseRelocationList* owner, IMAGE_BASE_RELOCATION* raw)
	: owner_(owner), raw_(raw)
{
}

ImageBaseRelocationFieldList ImageBaseRelocationListNode::Fields() const
{
	return { owner_->image_, raw_ };
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

bool ImageBaseRelocationListNode::operator==(const ImageBaseRelocationListNode& right) const
{
	return owner_ == right.owner_ && raw_ == right.raw_;
}

bool ImageBaseRelocationListNode::operator!=(const ImageBaseRelocationListNode& right) const
{
	return !operator==(right);
}

ImageBaseRelocationListNode& ImageBaseRelocationListNode::operator*()
{
	return *this;
}

uint32_t ImageBaseRelocationListNode::VirtualAddress() const
{
	return raw()->VirtualAddress;
}

uint32_t ImageBaseRelocationListNode::SizeOfBlock() const
{
	return raw()->SizeOfBlock;
}

ImageBaseRelocationFieldList::ImageBaseRelocationFieldList(Image* image, IMAGE_BASE_RELOCATION* raw)
	: image_(image), raw_(raw)
{
}

uint16_t* ImageBaseRelocationFieldList::RawFields() const
{
	return reinterpret_cast<uint16_t*>(reinterpret_cast<char*>(raw_) + sizeof(*raw_));
}

size_t ImageBaseRelocationFieldList::size() const
{
	return (raw_->SizeOfBlock - sizeof(*raw_)) / sizeof(uint16_t);
}

ImageBaseRelocationFieldListNode ImageBaseRelocationFieldList::begin() const
{
	return { const_cast<ImageBaseRelocationFieldList*>(this), RawFields() };
}

ImageBaseRelocationFieldListNode ImageBaseRelocationFieldList::end() const
{
	return { const_cast<ImageBaseRelocationFieldList*>(this), RawFields() + size() };
}

ImageBaseRelocationFieldListNode::ImageBaseRelocationFieldListNode(ImageBaseRelocationFieldList* owner,
	uint16_t* raw)
	: owner_(owner), raw_(raw)
{
}

RelBasedType ImageBaseRelocationFieldListNode::Type() const
{
	switch (*raw_ >> 12)
	{
	case IMAGE_REL_BASED_ABSOLUTE:
		return RelBasedType::kAbsolute;
	case IMAGE_REL_BASED_HIGHLOW:
		return RelBasedType::kHighLow;
	case IMAGE_REL_BASED_DIR64:
		return RelBasedType::kDir64;
	default:
		throw std::exception("Unsupported relocation based type!");
	}
}

uint16_t ImageBaseRelocationFieldListNode::Offset() const
{
	return *raw_ & 0xFFF;
}

uint32_t ImageBaseRelocationFieldListNode::Rva() const
{
	return owner_->raw()->VirtualAddress + Offset();
}

const uint32_t* ImageBaseRelocationFieldListNode::ResolveAddress32() const
{
	return reinterpret_cast<const uint32_t*>(owner_->image_->RvaToPoint(Rva()));
}

const uint64_t* ImageBaseRelocationFieldListNode::ResolveAddress64() const
{
	return reinterpret_cast<const uint64_t*>(ResolveAddress32());
}

uint32_t* ImageBaseRelocationFieldListNode::ResolveAddress32()
{
	return reinterpret_cast<uint32_t*>(owner_->image_->RvaToPoint(Rva()));
}

uint64_t* ImageBaseRelocationFieldListNode::ResolveAddress64()
{
	return reinterpret_cast<uint64_t*>(ResolveAddress32());
}

ImageBaseRelocationFieldListNode& ImageBaseRelocationFieldListNode::operator++()
{
	++raw_;
	return *this;
}

ImageBaseRelocationFieldListNode ImageBaseRelocationFieldListNode::operator++(int)
{
	auto tmp = *this;
	++*this;
	return tmp;
}

ImageBaseRelocationFieldListNode& ImageBaseRelocationFieldListNode::operator--()
{
	--raw_;
	return *this;
}

ImageBaseRelocationFieldListNode ImageBaseRelocationFieldListNode::operator--(int)
{
	auto tmp = *this;
	--*this;
	return tmp;
}

bool ImageBaseRelocationFieldListNode::operator==(const ImageBaseRelocationFieldListNode& right) const
{
	return owner_ == right.owner_ && raw_ == right.raw_;
}

bool ImageBaseRelocationFieldListNode::operator!=(const ImageBaseRelocationFieldListNode& right) const
{
	return !operator==(right);
}

ImageBaseRelocationFieldListNode& ImageBaseRelocationFieldListNode::operator*()
{
	return *this;
}

ImageBaseRelocationFieldListNode& ImageBaseRelocationFieldListNode::operator[](size_t index)
{
	raw_ += index;
	return *this;
}
}
