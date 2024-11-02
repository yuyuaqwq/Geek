#pragma once
#include <cstdint>
#include <Windows.h>

#include <geek/pe/image_data_directory.h>

namespace geek {
class Image;

enum class MagicType
{
	kHdr32,
	kHdr64,
	kRomHdr
};

class ImageOptionalHeader
{
public:
	ImageOptionalHeader(Image* image);

	const IMAGE_OPTIONAL_HEADER32* raw32() const { return raw_; }
	const IMAGE_OPTIONAL_HEADER64* raw64() const { return reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(raw_); }
	IMAGE_OPTIONAL_HEADER32* raw32() { return raw_; }
	IMAGE_OPTIONAL_HEADER64* raw64() { return reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(raw_); }

	ImageDataDirectory DataDirectory() const;

	MagicType Magic() const;

	uint32_t SizeOfImage() const;
	uint32_t SizeOfHeaders() const;
	uint64_t ImageBase() const;
	uint32_t SectionAlignment() const;
	uint32_t AddressOfEntryPoint() const;

	uint32_t CheckSum() const;
	void SetCheckSum(uint32_t sum);

	void SetImageBase(uint64_t base);
	void SetEntryPointAddress(uint32_t address);

private:
	Image* image_;
	IMAGE_OPTIONAL_HEADER32* raw_;
};
}
