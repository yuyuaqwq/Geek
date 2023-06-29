#ifndef GEEK_FILE_FILE_H_
#define GEEK_FILE_FILE_H_

#include <string>
#include <vector>
#include <fstream>

#ifndef GEEK_STD
#define GEEK_STD std::
#endif // GEEK_STD

namespace Geek {

class File {
public:
	enum class Status {
		kNormal = 0,
		kInvalidPath,
	};

public:
	File(const GEEK_STD wstring& path, GEEK_STD ios_base::openmode mode = GEEK_STD ios_base::in | GEEK_STD ios_base::out) {
		m_fs.open(path.c_str(), mode);
		if (!m_fs.is_open()) {
			m_status = Status::kInvalidPath;
			return;
		}
		m_status = Status::kNormal;
	}
	~File() {
		m_fs.close();
	}

public:
	GEEK_STD vector<char> Read(uint32_t offset = 0, uint32_t len = 0) {
		GEEK_STD vector<char> ret;
		if (m_status != Status::kNormal) {
			return ret;
		}
		if (len == 0) {
			m_fs.seekg(offset, GEEK_STD ios_base::end);
			len = m_fs.tellg();
		}
		m_fs.seekg(offset, GEEK_STD ios_base::beg);
		ret.resize(len);
		m_fs.read(ret.data(), len);
		return ret;
	}

	bool Write(const GEEK_STD vector<uint8_t>& buf, uint32_t offset = 0) {
		if (m_status != Status::kNormal) {
			return false;
		}
		m_fs.seekg(offset, GEEK_STD ios_base::beg);
		m_fs.write((char*)buf.data(), buf.size());
		return true;
	}

	bool Ok() {
		return m_status == Status::kNormal;
	}

private:
	Status m_status;
	GEEK_STD fstream m_fs;
};

} // namespace Geek

#endif // GEEK_FILE_FILE_H_