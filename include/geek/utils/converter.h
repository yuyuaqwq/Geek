#ifndef GEEK_UTILS_CONVERTER_H_
#define GEEK_UTILS_CONVERTER_H_

#include <string>
#include <vector>

namespace geek {

class Convert {
public:
    static std::string Utf16leToUtf8(const std::wstring& str);

    static std::wstring Utf8ToUtf16le(const std::string& str);

    static std::string Utf16leToAnsi(const std::wstring& str);

    static std::wstring AnsiToUtf16le(const std::string& str);

    static std::string AnsiToUtf8(const std::string& str);

    static std::string Base64Encode(const void* input, size_t size, const char* codes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=");

    static std::vector<uint8_t> Base64Decode(const char* input, size_t size, const char* codes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=");

    static std::string ToLowercase(std::string_view str);
    static std::wstring ToLowercase(std::wstring_view str);

    static std::string ToUppercase(std::string_view str);
    static std::wstring ToUppercase(std::wstring_view str);

    static std::string ToHexString(const void* buf, size_t size);
};

} // namespace geek

#endif // GEEK_UTILS_CONVERTER_H_