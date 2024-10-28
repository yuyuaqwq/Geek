#include <geek/pe/image_nt_header.h>

#include "image_impl.h"

namespace geek {
ImageNtHeader::ImageNtHeader(Image* owner_image)
	: owner_image_(owner_image)
{
	raw_ = owner_image_->impl_->nt_header_;
}

ImageOptionalHeader ImageNtHeader::OptionalHeader() const
{
	return { owner_image_ };
}
}
