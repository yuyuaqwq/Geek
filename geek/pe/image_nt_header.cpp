#include <geek/pe/image_nt_header.h>

#include "image_impl.h"

namespace geek {
ImageNtHeader::ImageNtHeader(Image* image)
	: image_(image)
{
	raw_ = image_->impl_->nt_header_;
}

ImageOptionalHeader ImageNtHeader::OptionalHeader() const
{
	return { image_ };
}
}
