#ifndef GEEK_SIGNATURE_CODE_SIGNATURE_CODE_H_
#define GEEK_SIGNATURE_CODE_SIGNATURE_CODE_H_



#include <string>
#include <vector>

#include <Geek/Process/Process.hpp>


namespace geek{

/*
* 特征码类
*/
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

	/*
	* 限定大小查找特征码
	*/

	PVOID64 Search(PVOID64 startAddress, size_t size, const std::string& hexStringData) {
		std::vector<SignatureElement> signature;
		size_t offset = 0, totalLength = StringToElement(hexStringData, signature, offset);

		size_t SignatureSize = signature.size();
		if (!SignatureSize) return nullptr;

		std::vector<char> buf;
		int64_t base = 0;
		if (!m_process->IsCur()) {
			buf = m_process->ReadMemory(startAddress, size);
			if (buf.empty()) {
				return nullptr;
			}
			PVOID64 newStartAddress = buf.data();
			base = ((int64_t)startAddress - (int64_t)newStartAddress);
			startAddress = newStartAddress;
		}

		for (size_t i = 0; i < size; ++i) {
			uint64_t currentPos = (uint64_t)startAddress + i;
			uint64_t returnPos = currentPos;
			if (i + totalLength > size) break;
			bool match = true;

			for (size_t j = 0; j < SignatureSize; ++j) {
				size_t length = signature[j].length;

				if (signature[j].type == SignatureElementType::kWhole) {
					int ret = memcmp_ex((void*)currentPos, signature[j].data.data(), length);
					if (ret == 1) {
						match = false;
						break;
					}
					else if (ret == 2) {
						return nullptr;
					}

				}
				currentPos = currentPos + length;
			}
			if (match) {
				return (PVOID)(base + returnPos + offset);
			}

		}
		return nullptr;

	}

	/*
	* 限定范围查找特征码
	*/
	PVOID64 Search(PVOID64 startAddress, PVOID64 endAddress, const std::string& hexStringData) {
		return Search(startAddress, (uint64_t)endAddress - (uint64_t)startAddress + 1, hexStringData);
	}


private:

	static unsigned int DecStringToUInt(const std::string& str, size_t* i = nullptr, const unsigned char* endCharArr = nullptr, size_t endCharArrSize = 0) {
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
			//如果设置了结束字符，除开结束字符其他的一律不管
			else if (endCharArr) {
				for (size_t j = 0; j < endCharArrSize; ++j) {
					if (c == endCharArr[j]) return sum;
				}
			}
			//不需要-1，因为计数本来就要比索引多1
			else break;

		}
		return sum;
	}

	static int __cdecl memcmp_ex(void const* _Buf1, void const* _Buf2, size_t _Size) {
		__try {
			if (memcmp(_Buf1, _Buf2, _Size)) {
				return 1;
			}
			else {
				return 0;
			}

		}
		__except (1) {
			return 2;
		}
	}


	/*
	* 将特征码字符串转换为Element
	* 标准格式示例： "48 &?? ?? 65*20 88"
	* &表示返回时的会以此字节为起始地址，加在字节前面即可，示例中即偏移为1
	*	以最后一个&为准
	* ??表示模糊匹配此字节
	* *xx表示上一个字节的重复次数，示例就是重复0x65 20次，是十进制
	*/
	size_t StringToElement(const std::string& hexStringData, std::vector<SignatureElement>& signature, size_t& offset) {
		bool first = true;
		unsigned char sum = 0;
		SignatureElement tempSignatureElement;
		tempSignatureElement.length = 0;
		SignatureElementType oldType = SignatureElementType::kNone, newType = SignatureElementType::kNone;
		size_t totalLength = 0;

		//遍历字符
		for (size_t i = 0; i < hexStringData.length(); ++i) {
			unsigned char c = hexStringData[i];
			bool validChar = true;
			if (c >= 0x30 && c <= 0x39) {
				c -= 0x30;
				newType = SignatureElementType::kWhole;
			}
			else if (c >= 0x41 && c <= 0x46) {
				c = c - 0x37;
				newType = SignatureElementType::kWhole;
			}
			else if (c >= 0x61 && c <= 0x66) {
				c = c - 0x57;
				newType = SignatureElementType::kWhole;
			}
			else if (c == '?') {
				newType = SignatureElementType::kVague;
			}
			else {
				if (c == '&') {
					offset = totalLength + tempSignatureElement.length;
				}
				else if (c == '*' && i + 1 < hexStringData.length()) {
					// 如果*号后面还有字符，将其视作重复次数
					size_t countInt;
					unsigned int lenInt = DecStringToUInt(&hexStringData[i] + 1, &countInt) - 1;
					if (countInt) {
						if (oldType == SignatureElementType::kWhole && tempSignatureElement.data.size() > 0) {
							unsigned char repC = tempSignatureElement.data[tempSignatureElement.data.size() - 1];
							for (size_t j = 0; j < lenInt; ++j) {
								tempSignatureElement.data.push_back(repC);
							}
						}
						tempSignatureElement.length += lenInt;
						i += countInt;
					}
						
				}

				// 无效字符，不需要检测类型
				validChar = false;
				goto _PushChar;
			}

			if (oldType == SignatureElementType::kNone) {
				// 如果旧类型未初始化，将新类型赋值给旧类型
				oldType = newType;
			}

			// 旧字符类型和新字符类型不同时，需要添加新的匹配单元
			else if (oldType != newType) {
				tempSignatureElement.type = oldType;
				totalLength += tempSignatureElement.length;
				signature.push_back(tempSignatureElement);

				oldType = newType;
				tempSignatureElement.length = 0;
				tempSignatureElement.data.clear();
			}

		_PushChar:
			// 如果原先类型是精确匹配，则添加字符
			if (oldType == SignatureElementType::kWhole) {
				if (first && validChar) {
					sum = c << 4;
					first = false;
				}
				else if (!first) {
					first = true;
					// 如果是无效字符，说明玩家并未提供连续的两个有效字符，将修正第一个有效字符的值
					validChar ? sum += c : sum >>= 4;
					tempSignatureElement.data.push_back(sum);
					++tempSignatureElement.length;
				}

				// 最后一种情况就是，即未开始拼接字节，且是无效字符，直接无视即可
			}

			// 模糊匹配，是第二个符号就直接递增长度
			else if (oldType == SignatureElementType::kVague) {
				if (first && validChar) {
					first = false;
				}
				else if (!first) {
					first = true;
					++tempSignatureElement.length;
				}
			}

		}

		//如果有未完成的字符，则推入
		if (!first) {
			if (oldType == SignatureElementType::kWhole) {
				tempSignatureElement.data.push_back(sum >> 4);
			}
			++tempSignatureElement.length;
		}

		//有匹配单元，推入
		if (tempSignatureElement.length > 0 || tempSignatureElement.data.size() > 0) {
			tempSignatureElement.type = oldType;
			totalLength += tempSignatureElement.length;
			signature.push_back(tempSignatureElement);
		}

		return totalLength;
	}

private:
	size_t m_offset;
	Process* m_process;

};

} // namespace geek

#endif // GEEK_SIGNATURE_CODE_SIGNATURE_CODE_H_