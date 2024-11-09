#pragma once
#include <sstream>
#include <vector>

namespace geek {

class StrUtil {
public:
    template<class... Args>
    static std::string Combine(const Args&... args) {
        std::stringstream ss;
        (ss << ... << args);
        return ss.str();
    }
    template<class... Args>
    static std::wstring WCombine(const Args&... args) {
        std::wstringstream wss;
        (wss << ... << args);
        return wss.str();
    }

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

    static std::string ToHexString(uint64_t val, int reserve = 8);
    static std::wstring ToHexWString(uint64_t val, int reserve = 8);
};

} // namespace geek