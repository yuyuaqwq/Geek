#pragma once
#include <Windows.h>
#include <geek/pe/data_directory/image_base_relocation.h>

namespace geek
{
class Image;
class ImageExportDirectory
{
public:
	ImageExportDirectory(Image* image);

private:
	Image* image_;
	IMAGE_EXPORT_DIRECTORY* raw_;
};

class ImageDataDirectory
{
public:
	ImageDataDirectory(Image* image);

	const IMAGE_DATA_DIRECTORY* raw() const { return raw_; }
	IMAGE_DATA_DIRECTORY* raw() { return raw_; }

	ImageBaseRelocationList BaseRelocations() const;
	ImageExportDirectory ExportDirectory() const;

private:
	Image* image_;
	IMAGE_DATA_DIRECTORY* raw_;
};
}
