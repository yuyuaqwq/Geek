#include <geek/error.h>
#include "errordefs.h"
#include <Windows.h>

namespace geek {
namespace {
ErrorType error_type;
uint32_t error_code;
const char* where;
}

namespace internal {
void UpdateWinError(const char* w)
{
	error_code = GetLastError();
	where = w;
	error_type = ErrorType::Win;
}

void UpdateNtError(uint32_t e, const char* w)
{
	error_code = e;
	where = w;
	error_type = ErrorType::Nt;
}
}

ErrorType LastError::TypeOfError()
{
}

uint32_t LastError::Code()
{
	return error_code;
}

std::string LastError::Message()
{
	//TODO Message
	return {};
}

std::string_view LastError::Where()
{
	return where;
}
}
