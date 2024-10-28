#include <assert.h>
#include <geek/pe/image_data_directory.h>

#include "image_impl.h"

namespace geek {
ImageDataDirectory::ImageDataDirectory(Image* owner_image)
	: owner_image_(owner_image)
{
	if (owner_image_->IsPE32())
	{
		raw_ = owner_image_->NtHeader().OptionalHeader().raw32()->DataDirectory;
	}
	else
	{
		raw_ = owner_image_->NtHeader().OptionalHeader().raw64()->DataDirectory;
	}
}

ImageBaseRelocationList ImageDataDirectory::BaseRelocations() const
{
	return { owner_image_ };
}

ImageExportDirectory ImageDataDirectory::ExportDirectory() const
{
	return { owner_image_ };
}


ImageExportDirectory::ImageExportDirectory(Image* owner_image)
	: owner_image_(owner_image)
{
	auto& dir = owner_image_->NtHeader().OptionalHeader().DataDirectory().raw()[IMAGE_DIRECTORY_ENTRY_EXPORT];
	raw_ = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(owner_image_->RvaToPoint(dir.VirtualAddress));
}
}
