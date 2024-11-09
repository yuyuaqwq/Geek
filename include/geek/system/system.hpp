#pragma once
#include <string>
#include <vector>

#include <Windows.h>

#include <geek/file/file.hpp>

namespace geek {

class System {
public:
    static std::wstring GetEnvironmentVariable(std::wstring name) {
        std::vector<wchar_t> buf(128, L'\0');
        do {
            buf.resize(buf.size() * 2, L'\0');
            ::GetEnvironmentVariableW(name.c_str(), (LPWSTR)buf.data(), MAX_PATH);
        } while (GetLastError() == ERROR_INSUFFICIENT_BUFFER);
        return buf.data();
    }
};

} // namespace Geek