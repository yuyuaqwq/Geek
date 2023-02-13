#ifndef GEEK_FILE_FILE_H_
#define GEEK_FILE_FILE_H_

#include <fstream>
#include <vector>

namespace geek {

class File {
public:
	enum class Status {
		kNormal = 0,
		kInvalidPath,
	};

public:
	File(const std::wstring& path, std::ios_base::openmode mode = std::ios::in | std::ios::out) {
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
	std::vector<char> Read(uint32_t offset = 0, uint32_t len = 0) {
		std::vector<char> ret;
		if (m_status != Status::kNormal) {
			return ret;
		}
		if (len == 0) {
			m_fs.seekg(offset, std::ios::end);
			len = m_fs.tellg();
		}
		m_fs.seekg(offset, std::ios::beg);
		ret.resize(len);
		m_fs.read(ret.data(), len);
		return ret;
	}

	bool Write(const std::vector<char>& buf, uint32_t offset = 0) {
		if (m_status != Status::kNormal) {
			return false;
		}
		m_fs.seekg(offset, std::ios::beg);
		m_fs.write(buf.data(), buf.size());
		return true;
	}

private:
	Status m_status;
	std::fstream m_fs;
};

} // namespace geek

#endif // GEEK_FILE_FILE_H_