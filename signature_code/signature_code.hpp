#ifndef GEEK_SIGNATURE_CODE_SIGNATURE_CODE_H_
#define GEEK_SIGNATURE_CODE_SIGNATURE_CODE_H_

#include <string>
#include <vector>

#include <geek/process/process.hpp>


namespace Geek{


class SignatureCode {
private:
    enum class SignatureElementType {
        kNone,
        kWhole,
        kVague
    };

    struct SignatureElement {
        SignatureElementType type;
        size_t length;
        std::vector<unsigned char> data;
    };


public:
    SignatureCode() : m_process { nullptr } { }
    explicit SignatureCode(Process* process) : m_process{ process } { }
    ~SignatureCode() { }

public:
    uint64_t Search(uint64_t start_address, size_t size, const std::string& hex_string_data) {
        std::vector<SignatureElement> signature;
        size_t offset = 0, total_len = StringToElement(hex_string_data, signature, offset);

        size_t signature_size = signature.size();
        if (!signature_size) return 0;

        std::vector<uint8_t> buf;
        uint64_t base = 0;
        if (!m_process->IsCur()) {
            buf = m_process->ReadMemory(start_address, size);
            if (buf.empty()) {
                return 0;
            }
            uint64_t new_start_address = (uint64_t)buf.data();
            base = ((uint64_t)start_address - (uint64_t)new_start_address);
            start_address = new_start_address;
        }

        for (size_t i = 0; i < size; ++i) {
            uint64_t cur_pos = start_address + i;
            uint64_t ret_pos = cur_pos;
            if (i + total_len > size) break;
            bool match = true;
            for (size_t j = 0; j < signature_size; ++j) {
                size_t length = signature[j].length;
                if (signature[j].type == SignatureElementType::kWhole) {
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
        return 0;

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
    size_t StringToElement(const std::string& hex_string_data, std::vector<SignatureElement>& signature, size_t& offset) {
        bool first = true;
        unsigned char sum = 0;
        SignatureElement temp_signature_element;
        temp_signature_element.length = 0;
        SignatureElementType oldType = SignatureElementType::kNone, newType = SignatureElementType::kNone;
        size_t total_length = 0;

        for (size_t i = 0; i < hex_string_data.length(); ++i) {
            unsigned char c = hex_string_data[i];
            bool validChar = true;
            if (c >= '0' && c <= '9') {
                c -= '0';
                newType = SignatureElementType::kWhole;
            }
            else if (c >= 'a' && c <= 'f') {
                c = c - 'a' + 10;
                newType = SignatureElementType::kWhole;
            }
            else if (c >= 'A' && c <= 'F') {
                c = c - 'A' + 10;
                newType = SignatureElementType::kWhole;
            }
            else if (c == '?') {
                newType = SignatureElementType::kVague;
            }
            else {
                if (c == '&') {
                    offset = total_length + temp_signature_element.length;
                }
                else if (c == '*' && i + 1 < hex_string_data.length()) {
                    size_t countInt;
                    unsigned int lenInt = DecStringToUInt(&hex_string_data[i] + 1, &countInt) - 1;
                    if (countInt) {
                        if (oldType == SignatureElementType::kWhole && temp_signature_element.data.size() > 0) {
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

            if (oldType == SignatureElementType::kNone) {
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
            if (oldType == SignatureElementType::kWhole) {
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

            else if (oldType == SignatureElementType::kVague) {
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
            if (oldType == SignatureElementType::kWhole) {
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
    size_t m_offset;
    Process* m_process;
};

} // namespace Geek

#endif // GEEK_SIGNATURE_CODE_SIGNATURE_CODE_H_