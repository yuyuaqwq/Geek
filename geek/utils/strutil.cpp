#include <geek/utils/strutil.h>

#include <Windows.h>

#include <iomanip>
#include <algorithm>
#include <sstream>

namespace geek {
std::string StrUtil::Utf16leToUtf8(const std::wstring& str)
{
	int len = WideCharToMultiByte(CP_UTF8, 0, str.c_str(), -1, NULL, 0, NULL, NULL);
	if (!len) {
		return "";
	}
	std::vector<char> buf(len);
	if (!WideCharToMultiByte(CP_UTF8, 0, str.c_str(), -1, buf.data(), len, NULL, NULL)) {
		return ""; 
	}
	return buf.data();
}

std::wstring StrUtil::Utf8ToUtf16le(const std::string& str)
{
	int len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
	if (!len) {
		return L"";
	}
	std::vector<wchar_t> buf(len);
	if (!MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, buf.data(), len)) {
		return L"";
	}
	return buf.data();
}

std::string StrUtil::Utf16leToAnsi(const std::wstring& str)
{
	int len = WideCharToMultiByte(CP_ACP, 0, str.c_str(), -1, NULL, 0, NULL, NULL);
	if (!len) {
		return ""; 
	}
	std::vector<char> buf(len);
	if (!WideCharToMultiByte(CP_ACP, 0, str.c_str(), -1, buf.data(), len, NULL, NULL)) {
		return ""; 
	}
	return buf.data();
}

std::wstring StrUtil::AnsiToUtf16le(const std::string& str)
{
	int len = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, NULL, 0);
	if (!len) {
		return L""; 
	}
	std::vector<wchar_t> buf(len);
	if (!MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, buf.data(), len)) {
		return L""; 
	}
	return buf.data();
}

std::string StrUtil::AnsiToUtf8(const std::string& str)
{
	auto str_utf16le = AnsiToUtf16le(str);
	return Utf16leToUtf8(str_utf16le);
}

std::string StrUtil::Base64Encode(const void* input, size_t size, const char* codes)
{
	const unsigned char* c_input = (const unsigned char*)input;
	std::string output;
        
	size_t i = 0;
	for (i = 0; i < size / 3 * 3; i += 3) {
		output += codes[(c_input[i] >> 2)];
		output += codes[(((c_input[i] & 0x3) << 4) | ((c_input[i + 1] & 0xf0) >> 4))];
		output += codes[(((c_input[i + 1] & 0xf) << 2) | ((c_input[i + 2] & 0xc0) >> 6))];
		output += codes[(c_input[i + 2] & 0x3f)];
	}

	if (size - i == 1) {
		output += codes[(c_input[i] >> 2)];
		output += codes[((c_input[i] & 0x3) << 4)];
		output += codes[64];
		output += codes[64];
	}
	else if (size - i == 2) {
		output += codes[(c_input[i] >> 2)];
		output += codes[(((c_input[i] & 0x3) << 4) | ((c_input[i + 1] & 0xf0) >> 4))];
		output += codes[((c_input[i + 1] & 0xf) << 2)];
		output += codes[64];
	}
	return output;
}

std::vector<uint8_t> StrUtil::Base64Decode(const char* input, size_t size, const char* codes)
{
	const unsigned char* c_input = (const unsigned char*)input;
	std::vector<uint8_t> output;

	char codes_table[256] = { 0 };
	for (int i = 0; i < 64; i++) {
		codes_table[codes[i]] = i;
	}

	size_t i = 0;
	for (i = 0; i < size / 4 * 4; i += 4) {
		uint8_t c1, c2, c3;
		c1 = (codes_table[input[i]] << 2) | ((codes_table[input[i+1]] >> 4) & 0x3);
		output.push_back(c1);
		if (input[i + 2] == codes[64]) {
			break;
		}
		c2 = ((codes_table[input[i+1]] & 0xf) << 4) | ((codes_table[input[i+2]] >> 2) & 0xf);
		output.push_back(c2);
		if (input[i + 3] == codes[64]) {
			break;
		}
		c3 = ((codes_table[input[i+2]] & 0x3) << 6) | ((codes_table[input[i+3]]));
		output.push_back(c3);
	}
	return output;
}

std::string StrUtil::ToLowercase(std::string_view str)
{
	std::string total(str.size(), '\0');
	std::transform(str.begin(), str.end(), total.begin(), [](auto ch) { return std::tolower(ch); });
	return total;
}

std::wstring StrUtil::ToLowercase(std::wstring_view str)
{
	std::wstring total(str.size(), L'\0');
	std::transform(str.begin(), str.end(), total.begin(), [](auto ch) { return std::tolower(ch); });
	return total;
}

std::string StrUtil::ToUppercase(std::string_view str)
{
	std::string total(str.size(), '\0');
	std::transform(str.begin(), str.end(), total.begin(), [](auto ch) { return std::toupper(ch); });
	return total;
}

std::wstring StrUtil::ToUppercase(std::wstring_view str)
{
	std::wstring total(str.size(), L'\0');
	std::transform(str.begin(), str.end(), total.begin(), [](auto ch) { return std::toupper(ch); });
	return total;
}

std::string StrUtil::ToHexString(uint64_t val, int reserve)
{
	std::stringstream ss;
	ss << std::hex << std::uppercase << std::setw(reserve) << std::setfill('0') << (val & 0xFFFFFFFF);
	return ss.str();
}

std::wstring StrUtil::ToHexWString(uint64_t val, int reserve)
{
	std::wstringstream ss;
	ss << std::hex << std::uppercase << std::setw(reserve) << std::setfill(L'0') << (val & 0xFFFFFFFF);
	return ss.str();
}
}
