#ifndef GEEK_STRING_STRING_H_
#define GEEK_STRING_STRING_H_

#include <exception>
#include <memory>
#include <string>
#include <vector>

#ifdef _MSC_VER
#include <Windows.h>
#endif

namespace geek {

class String {
public:
#ifdef _MSC_VER
  static std::string Utf16leToUtf8(const std::wstring& str) {
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

  static std::wstring Utf8ToUtf16le(const std::string& str) {
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

  static std::string Utf16leToAnsi(const std::wstring& str) {
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

  static std::wstring AnsiToUtf16le(const std::string& str) {
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

  static std::string AnsiToUtf8(const std::string& str) {
    auto str_utf16le = AnsiToUtf16le(str);
    return Utf16leToUtf8(str_utf16le);
  }
#endif

  static std::string Base64Encode(const void* input, size_t size, const char* codes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") {
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

  static std::vector<uint8_t> Base64Decode(const char* input, size_t size, const char* codes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") {
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


  template<typename T1, typename T2>
  static std::vector<T1> Split(const T1& str, const T2& token, bool no_empty = false) {
    std::vector<T1> ret_arr;
    auto token_ = (T1)token;
    if (str.size() == 0) {
      return ret_arr;
    }
    size_t token_len = token_.size();
    if (token_len == 0) {
      ret_arr.push_back(str);
      return ret_arr;
    }
    size_t pos = 0, last_pos = 0;
    int size;
    pos = str.find(token_, last_pos);
    while (pos != -1) {
      size = pos - last_pos;
      if (!no_empty || size > 0) {
        ret_arr.push_back(str.substr(last_pos, size));
      }

      last_pos = pos + token_len;
      pos = str.find(token_, last_pos);
    }

    if (last_pos < str.length()) {
      ret_arr.push_back(str.substr(last_pos));
    }

    return ret_arr;
  }

  template<typename T1, typename T2>
  static T1 Replace(const T1& str, const T2& replace, const T2& target) {
    auto new_str = str;
    auto replace_ = (T1)replace;
    auto target_ = (T1)target;
    size_t pos = 0;
    pos = new_str.find(replace);
    while (pos != -1) {
      new_str = new_str.replace(pos, replace_.size(), target_.c_str());
      pos = new_str.find(replace, pos + target_.size() + 1);
    }
    return new_str;
  }


  template<typename T>
  static T DeleteHeadSpace(const T& str) {
    size_t i = 0;
    auto temp = str;
    for (; i < temp.length(); i++) {
      if (temp[i] != ' ') {
        break;
      }
    }
    temp.erase(0, i);
    return temp;
  }

  template<typename T>
  static T DeleteTailSpace(const T& str) {
    auto temp = str;
    size_t i = temp.length() - 1;
    for (; i >= 0; i--) {
      if (temp[i] != ' ') {
        break;
      }
    }
    temp.erase(i + 1);
    return temp;
  }

  template<typename T>
  static T DeleteHeadTailSpace(const T& str) {
    auto temp = DeleteHeadSpace(str);
    return DeleteTailSpace(temp);
  }

  template <typename T>
  static T ToLowercase(const T& str) {
    auto temp = str;
    for (auto& c : temp) {
      if (c >= 0x41 && c <= 0x5a) {
        c += 0x20;
      }
    }
    return temp;
  }

  template <typename T>
  static T ToUppercase(const T& str) {
    auto temp = str;
    for (auto& c : temp) {
      if (c >= 0x61 && c <= 0x7a) {
        c -= 0x20;
      }
    }
    return temp;
  }
};

} // namespace geek

#endif // GEEK_STRING_STRING_H_