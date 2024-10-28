#include <geek/pe/image_optional_header.h>

#include "image_impl.h"

#define GET_OPTIONAL_HEADER_FIELD(field, var) \
do{	\
	if (raw32()->Magic == 0x10b) \
		var = raw32()->##field;			\
	else /* (impl_->m_nt_header->OptionalHeader.Magic == 0x20b)*/ \
		var = raw64()->##field; \
} while(false)

#define SET_OPTIONAL_HEADER_FIELD(field, var) \
do { \
	using Type = decltype(raw32()->##field); \
	if (raw32()->Magic == 0x10b)  \
		raw32()->##field = static_cast<Type>(var); \
    else/* (impl_->m_nt_header->OptionalHeader.Magic == 0x20b)*/ \
		raw64()->##field = static_cast<Type>(var); \
} while(false)

namespace geek {
ImageOptionalHeader::ImageOptionalHeader(Image* owner_image)
	: owner_image_(owner_image)
{
	raw_ = &owner_image_->NtHeader().raw32()->OptionalHeader;
}

ImageDataDirectory ImageOptionalHeader::DataDirectory() const
{
	return { owner_image_ };
}

MagicType ImageOptionalHeader::Magic() const
{
	switch (raw32()->Magic)
	{
	case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		return MagicType::kHdr32;
	case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		return MagicType::kHdr64;
	case IMAGE_ROM_OPTIONAL_HDR_MAGIC:
		return MagicType::kRomHdr;
	default:
		throw std::exception("PE corruption!");
	}
}

uint32_t ImageOptionalHeader::SizeOfImage() const
{
	uint32_t v;
	GET_OPTIONAL_HEADER_FIELD(SizeOfImage, v);
	return v;
}

uint32_t ImageOptionalHeader::SizeOfHeaders() const
{
	uint32_t v;
	GET_OPTIONAL_HEADER_FIELD(SizeOfHeaders, v);
	return v;
}

uint64_t ImageOptionalHeader::ImageBase() const
{
	uint64_t v;
	GET_OPTIONAL_HEADER_FIELD(ImageBase, v);
	return v;
}

uint32_t ImageOptionalHeader::SectionAlignment() const
{
	uint32_t v;
	GET_OPTIONAL_HEADER_FIELD(SectionAlignment, v);
	return v;
}

uint32_t ImageOptionalHeader::AddressOfEntryPoint() const
{
	uint32_t v;
	GET_OPTIONAL_HEADER_FIELD(AddressOfEntryPoint, v);
	return v;
}

uint32_t ImageOptionalHeader::CheckSum() const
{
	uint32_t v;
	GET_OPTIONAL_HEADER_FIELD(CheckSum, v);
	return v;
}

void ImageOptionalHeader::SetCheckSum(uint32_t sum)
{
	SET_OPTIONAL_HEADER_FIELD(CheckSum, sum);
}

void ImageOptionalHeader::SetImageBase(uint64_t base)
{
	SET_OPTIONAL_HEADER_FIELD(ImageBase, base);
}

void ImageOptionalHeader::SetEntryPointAddress(uint32_t address)
{
	SET_OPTIONAL_HEADER_FIELD(AddressOfEntryPoint, address);
}
}
