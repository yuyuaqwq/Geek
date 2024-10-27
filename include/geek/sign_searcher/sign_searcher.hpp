#ifndef GEEK_SIGN_SEARCHER_HPP_
#define GEEK_SIGN_SEARCHER_HPP_

#include <string>
#include <vector>
#include <optional>

#include <geek/process/process.h>


namespace geek{

class SignSearcher {
private:
    enum class SignElementType {
        kNone,
        kWhole,
        kVague
    };

    struct SignElement {
        SignElementType type;
        size_t length;
        std::vector<unsigned char> data;
    };

public:
    SignSearcher() : process_handle_ { nullptr } { }
    explicit SignSearcher(Process* process) : process_handle_{ process } { }
    ~SignSearcher() { }

public:
    std::optional<uint64_t> Search(uint64_t start_address, size_t size, const std::string& hex_string_data) {
        std::vector<SignElement> signature;
        size_t offset = 0, total_len = StringToElement(hex_string_data, signature, offset);

        size_t signature_size = signature.size();
        if (!signature_size) return {};

        uint64_t base = 0;
        std::optional<std::vector<uint8_t>> buf;
        if (!process_handle_->IsCur()) {
            buf = process_handle_->ReadMemory(start_address, size);
            if (!buf) {
                return {};
            }
            uint64_t new_start_address = (uint64_t)buf.value().data();
            base = ((uint64_t)start_address - (uint64_t)new_start_address);
            start_address = new_start_address;
        }

        for (size_t i = 0; i < size; ++i) {
            uint64_t cur_pos = start_address + i;
            if (base + i == 0x13cdce0) {
                printf("???");
            }
            uint64_t ret_pos = cur_pos;
            if (i + total_len > size) break;
            bool match = true;
            for (size_t j = 0; j < signature_size; ++j) {
                size_t length = signature[j].length;
                if (signature[j].type == SignElementType::kWhole) {
                    if (IsBadReadPtr((void*)cur_pos, length)) {
                        match = false;
                        break;
                    }
                    int ret = memcmp((void*)cur_pos, signature[j].data.data(), length);
                    if (ret != 0) {
                        match = false;
                        break;
                    }
                }
                cur_pos = cur_pos + length;
            }
            if (match) {
                return (base + ret_pos + offset);
            }
        }
        return {};

    }


private:

    static unsigned int DecStringToUInt(const std::string& str, size_t* i = nullptr, const unsigned char* end_char_arr = nullptr, size_t end_char_arr_size = 0) {
        unsigned int sum = 0;
        if (!i) {
            size_t j;
            i = &j;
        }
        for (*i = 0; *i < str.length(); ++ * i) {
            unsigned char c = str[*i];
            if (c >= 0x30 && c <= 0x39) {
                c -= 0x30;
                sum = sum * 10 + c;
            }
            else if (end_char_arr) {
                for (size_t j = 0; j < end_char_arr_size; ++j) {
                    if (c == end_char_arr[j]) return sum;
                }
            }
            else break;

        }
        return sum;
    }

    static int __cdecl memcmp_ex(const void* buf1, const void* buf2, size_t size) {
        const char* buf1_ = (const char*)buf1;
        const char* buf2_ = (const char*)buf2;
        
        __try {
            for (int i = 0; i < size; i++) {
                if (buf1_[i] != buf2_[i]) {
                    return i;
                }
            }
            return -1;

        }
        __except (1) {
            return -2;
        }
    }


    /* 
    * "48 &?? ?? 65*20 88"
    * &表示返回的地址以此为准
    * *20表示重复20次，是十进制
    * ??表示模糊匹配
    */
    size_t StringToElement(const std::string& hex_string_data, std::vector<SignElement>& signature, size_t& offset) {
        bool first = true;
        unsigned char sum = 0;
        SignElement temp_signature_element;
        temp_signature_element.length = 0;
        SignElementType oldType = SignElementType::kNone, newType = SignElementType::kNone;
        size_t total_length = 0;

        for (size_t i = 0; i < hex_string_data.length(); ++i) {
            unsigned char c = hex_string_data[i];
            bool validChar = true;
            if (c >= '0' && c <= '9') {
                c -= '0';
                newType = SignElementType::kWhole;
            }
            else if (c >= 'a' && c <= 'f') {
                c = c - 'a' + 10;
                newType = SignElementType::kWhole;
            }
            else if (c >= 'A' && c <= 'F') {
                c = c - 'A' + 10;
                newType = SignElementType::kWhole;
            }
            else if (c == '?') {
                newType = SignElementType::kVague;
            }
            else {
                if (c == '&') {
                    offset = total_length + temp_signature_element.length;
                }
                else if (c == '*' && i + 1 < hex_string_data.length()) {
                    size_t countInt;
                    unsigned int lenInt = DecStringToUInt(&hex_string_data[i] + 1, &countInt) - 1;
                    if (countInt) {
                        if (oldType == SignElementType::kWhole && temp_signature_element.data.size() > 0) {
                            unsigned char repC = temp_signature_element.data[temp_signature_element.data.size() - 1];
                            for (size_t j = 0; j < lenInt; ++j) {
                                temp_signature_element.data.push_back(repC);
                            }
                        }
                        temp_signature_element.length += lenInt;
                        i += countInt;
                    }
                        
                }
                validChar = false;
                goto _PushChar;
            }

            if (oldType == SignElementType::kNone) {
                oldType = newType;
            }

            else if (oldType != newType) {
                temp_signature_element.type = oldType;
                total_length += temp_signature_element.length;
                signature.push_back(temp_signature_element);

                oldType = newType;
                temp_signature_element.length = 0;
                temp_signature_element.data.clear();
            }

        _PushChar:
            if (oldType == SignElementType::kWhole) {
                if (first && validChar) {
                    sum = c << 4;
                    first = false;
                }
                else if (!first) {
                    first = true;
                    validChar ? sum += c : sum >>= 4;
                    temp_signature_element.data.push_back(sum);
                    ++temp_signature_element.length;
                }
            }

            else if (oldType == SignElementType::kVague) {
                if (first && validChar) {
                    first = false;
                }
                else if (!first) {
                    first = true;
                    ++temp_signature_element.length;
                }
            }

        }

        if (!first) {
            if (oldType == SignElementType::kWhole) {
                temp_signature_element.data.push_back(sum >> 4);
            }
            ++temp_signature_element.length;
        }

        if (temp_signature_element.length > 0 || temp_signature_element.data.size() > 0) {
            temp_signature_element.type = oldType;
            total_length += temp_signature_element.length;
            signature.push_back(temp_signature_element);
        }

        return total_length;
    }

private:
    Process* process_handle_;
};

} // namespace Geek

#endif // GEEK_SIGN_SEARCHER_HPP_