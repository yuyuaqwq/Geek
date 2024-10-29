#include <assert.h>
#include <geek/pe/image_data_directory.h>

#include "image_impl.h"

namespace geek {
ImageDataDirectory::ImageDataDirectory(Image* image)
	: image_(image)
{
	if (image_->IsPE32())
	{
		raw_ = image_->NtHeader().OptionalHeader().raw32()->DataDirectory;
	}
	else
	{
		raw_ = image_->NtHeader().OptionalHeader().raw64()->DataDirectory;
	}
}

ImageBaseRelocationList ImageDataDirectory::BaseRelocations() const
{
	return { image_ };
}

ImageExportDirectory ImageDataDirectory::ExportDirectory() const
{
	return { image_ };
}


ImageExportDirectory::ImageExportDirectory(Image* image)
	: image_(image)
{
	auto& dir = image_->NtHeader().OptionalHeader().DataDirectory().raw()[IMAGE_DIRECTORY_ENTRY_EXPORT];
	raw_ = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(image_->RvaToPoint(dir.VirtualAddress));
}
}
