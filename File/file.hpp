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
		mFs.open(path.c_str(), mode);
		if (!mFs.is_open()) {
			mStatus = Status::kInvalidPath;
			return;
		}
		mStatus = Status::kNormal;
	}

	~File() {
		mFs.close();
	}

public:
	std::vector<char> Read(uint32_t offset = 0, uint32_t len = 0) {
		std::vector<char> ret;
		if (mStatus != Status::kNormal) {
			return ret;
		}
		if (len == 0) {
			mFs.seekg(offset, std::ios::end);
			len = mFs.tellg();
		}
		mFs.seekg(offset, std::ios::beg);
		ret.resize(len);
		mFs.read(ret.data(), len);
		return ret;
	}

	bool Write(const std::vector<char>& buf, uint32_t offset = 0) {
		if (mStatus != Status::kNormal) {
			return false;
		}
		mFs.seekg(offset, std::ios::beg);
		mFs.write(buf.data(), buf.size());
		return true;
	}

private:
	Status mStatus;
	std::fstream mFs;
};

} // namespace geek

#endif // GEEK_FILE_FILE_H_