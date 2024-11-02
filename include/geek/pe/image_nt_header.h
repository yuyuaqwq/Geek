#pragma once
#include <Windows.h>

#include <geek/pe/image_optional_header.h>

namespace geek {
class Image;

class ImageNtHeader
{
public:
	ImageNtHeader(Image* image);

	const IMAGE_NT_HEADERS32* raw32() const { return raw_; }
	const IMAGE_NT_HEADERS64* raw64() const { return reinterpret_cast<IMAGE_NT_HEADERS64*>(raw_); }
	IMAGE_NT_HEADERS32* raw32() { return raw_; }
	IMAGE_NT_HEADERS64* raw64() { return reinterpret_cast<IMAGE_NT_HEADERS64*>(raw_); }

	ImageOptionalHeader OptionalHeader() const;

private:
	Image* image_;
	IMAGE_NT_HEADERS32* raw_;
};
}
