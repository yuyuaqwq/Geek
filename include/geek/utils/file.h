#ifndef GEEK_FILE_FILE_H_
#define GEEK_FILE_FILE_H_

#include <string>
#include <vector>
#include <fstream>
#include <optional>

#include <Windows.h>

namespace geek {

class File {
public:
    File() = default;
    File(File&& file) noexcept;
    ~File();

    static std::optional<File> Open(std::wstring_view path, std::ios_base::openmode mode = std::ios_base::in | std::ios_base::out);

    std::vector<uint8_t> Read(uint32_t offset = 0, uint32_t len = 0);
    bool Write(const std::vector<uint8_t>& buf, uint32_t offset = 0);

    static std::wstring GetAppDirectory();
    static std::vector<std::wstring> EnumFiles(
        const std::wstring& findDirPath,
        bool getFilePath,
        bool getDirPath,
        bool getSubDir,
        const std::wstring& fileNameFilter = L"*.*",
        DWORD fileAttributesFilter = 0);
    static bool IsDirectory(const std::wstring& filePath);
    static bool IsFile(const std::wstring& filePath);
    static bool FileExists(const std::wstring& filePath);
    static std::wstring ExpandSysEnvsByName(const std::wstring& envsName);
    static std::wstring GetFileName(const std::wstring& filePath);
    /*
    * level < 0，表示从后向前，level > 0，表示从前向后
    */
    static std::wstring GetFileDir(const std::wstring& filePath, int level = -1);
    static uint64_t GetFileSize(const std::wstring& filePath);
    static FILETIME GetFileLastWriteTime(const std::wstring& filePath);
    static bool CopyFolder(const std::wstring& pstrFolder, const std::wstring& pstrDest);
    /* 删除目录及目录中的所有内容 */
    static bool DeleteFolder(const std::wstring& pstrFolder, bool recursive);
    static std::vector<uint8_t> ReadFile(const wchar_t* pFilePath, size_t size = -1);
    static bool WriteFile(const wchar_t* pFilePath, const uint8_t* lpBuff, int nLen, const wchar_t* mode = L"wb");

private:
    std::fstream fs_;
};

} // namespace geek

#endif // GEEK_FILE_FILE_H_