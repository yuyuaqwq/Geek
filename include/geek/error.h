#pragma once
#include <cstdint>
#include <string>

namespace geek {
enum class ErrorType
{
	Win,
	Nt,
	Geek
};

//TODO Ӧ�ô�����
class LastError {
public:
	static ErrorType TypeOfError();

	static uint32_t Code();
	static std::string Message();
	static std::string_view Where();
};
}
