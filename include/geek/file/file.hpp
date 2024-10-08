#ifndef GEEK_FILE_FILE_H_
#define GEEK_FILE_FILE_H_

#include <string>
#include <vector>
#include <fstream>
#include <optional>

#include <Windows.h>
#include <TlHelp32.h>
#include <UserEnv.h>
#pragma comment(lib, "UserEnv.lib")

#ifndef GEEK_STD
#define GEEK_STD std::
#endif // GEEK_STD

namespace Geek {

class File {
public:
    File() {

    }

    File(File&& file) : fs_{std::move(file.fs_)} {

    }

    ~File() {
        fs_.close();
    }

    static std::optional<File> Open(std::wstring_view path, GEEK_STD ios_base::openmode mode = GEEK_STD ios_base::in | GEEK_STD ios_base::out) {
        File temp{};
        temp.fs_.open(path.data(), mode);
        if (!temp.fs_.is_open()) {
            return {};
        }
        return temp;
    }

public:
    GEEK_STD vector<uint8_t> Read(uint32_t offset = 0, uint32_t len = 0) {
        GEEK_STD vector<uint8_t> ret;
        if (len == 0) {
            fs_.seekg(offset, GEEK_STD ios_base::end);
            len = fs_.tellg();
        }
        fs_.seekg(offset, GEEK_STD ios_base::beg);
        ret.resize(len);
        fs_.read((char*)ret.data(), len);
        return ret;
    }

    bool Write(const GEEK_STD vector<uint8_t>& buf, uint32_t offset = 0) {
        fs_.seekg(offset, GEEK_STD ios_base::beg);
        fs_.write((char*)buf.data(), buf.size());
        return true;
    }

    /*
    * static method
    */
    static std::wstring GetAppDirectory() {
        std::vector<wchar_t> buf(MAX_PATH, L'\0');
        do {
            buf.resize(buf.size() * 2, L'\0');
            GetCurrentDirectoryW(MAX_PATH, (LPWSTR)buf.data());
            // GetModuleFileNameW(nullptr, (LPWSTR)buf.data(), MAX_PATH);
        } while (GetLastError() == ERROR_INSUFFICIENT_BUFFER);
        std::wstring app_path = buf.data();
        // app_path = GetFileDir(app_path);
        return app_path;
    }

    static std::vector<std::wstring> EnumFiles(const std::wstring& findDirPath, bool getFilePath, bool getDirPath, bool getSubDir, const std::wstring& fileNameFilter = L"*.*", DWORD fileAttributesFilter = 0) {
        std::vector<std::wstring> out;
        std::wstring findDir = findDirPath;
        if (findDir[findDir.size() - 1] != L'\\') {
            findDir.push_back(L'\\');
        }
        WIN32_FIND_DATAW FindFileData;
        HANDLE hFind = FindFirstFileW((findDir + fileNameFilter).c_str(), &FindFileData);
        if (INVALID_HANDLE_VALUE == hFind) {
            return out;
        }
        std::wstring sepdir1 = L".", sepdir2 = L"..";
        do {
            std::wstring filePath = findDir + FindFileData.cFileName;
            if (FindFileData.dwFileAttributes & fileAttributesFilter) {
                continue;
            }
            if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (FindFileData.cFileName == sepdir1 || FindFileData.cFileName == sepdir2) {
                    continue;
                }
                if (getSubDir) {
                    for (auto& it : EnumFiles(filePath, getFilePath, getDirPath, getSubDir, fileNameFilter, fileAttributesFilter)) {
                        out.push_back(it);
                    }
                }
                if (getDirPath) {
                    out.push_back(filePath);
                }
            }
            else {
                if (getFilePath) {
                    out.push_back(filePath);
                }
            }
        } while (FindNextFileW(hFind, &FindFileData));
        FindClose(hFind);
        return out;
    }

    static bool IsDirectory(const std::wstring& filePath) {
        if (filePath.empty()) {
            return false;
        }
        auto copyPath = filePath;
        if (copyPath.at(copyPath.size() - 1) == L'\\') {
            copyPath.pop_back();
        }
        WIN32_FIND_DATAW FindFileData;
        HANDLE hFind = FindFirstFileW(copyPath.c_str(), &FindFileData);
        if (INVALID_HANDLE_VALUE == hFind) {
            return false;
        }
        FindClose(hFind);
        return FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY;
    }

    static bool IsFile(const std::wstring& filePath) {
        WIN32_FIND_DATAW FindFileData;
        HANDLE hFind = FindFirstFileW(filePath.c_str(), &FindFileData);
        if (INVALID_HANDLE_VALUE == hFind) {
            return false;
        }
        FindClose(hFind);
        return !(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
    }

    static bool FileExists(const std::wstring& filePath) {
        WIN32_FIND_DATAW FindFileData;
        HANDLE hFind = FindFirstFileW(filePath.c_str(), &FindFileData);
        if (INVALID_HANDLE_VALUE == hFind) {
            return false;
        }
        FindClose(hFind);
        return true;
    }

    static std::wstring ExpandSysEnvsByName(const std::wstring& envsName) {
        HANDLE hToken = nullptr;
        HANDLE hProcessSnap = nullptr;
        PROCESSENTRY32W pe32 = { 0 };
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcessSnap)
            return L"";
        if (!Process32FirstW(hProcessSnap, &pe32))
            return L"";
        do {
            if (_wcsicmp(pe32.szExeFile, L"explorer.exe") == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
                if (NULL == hProcess)
                    return L"";
                if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken))
                    return L"";
                CloseHandle(hProcessSnap);
                break;
            }
        } while (Process32NextW(hProcessSnap, &pe32));

        WCHAR szEnvsPath[MAX_PATH] = { 0 };
        if (!ExpandEnvironmentStringsForUserW(hToken, envsName.c_str(), szEnvsPath, MAX_PATH)) {
            return L"";
        }
        return szEnvsPath;
    }

    static std::wstring GetFileName(const std::wstring& filePath) {
        auto pos = filePath.rfind(L'\\');
        if (pos == -1) {
            return filePath;
        }
        return filePath.substr(pos + 1);
    }

    /*
    * level < 0，表示从后向前，level > 0，表示从前向后
    */
    static std::wstring GetFileDir(const std::wstring& filePath, int level = -1) {
        size_t pos;
        if (level > 0) {
            pos = -1;
            for (int i = 0; i < level; i++) {
                pos = filePath.find(L'\\', pos + 1);
                if (pos == -1) {
                    pos = filePath.find(L'/', pos + 1);
                    if (pos == -1) {
                        return L"";
                    }
                }
            }
        }
        else {
            level = -level;
            pos = 0;
            for (int i = 0; i < level; i++) {
                pos = filePath.rfind(L'\\', pos - 1);
                if (pos == -1) {
                    pos = filePath.find(L'/', pos - 1);
                    if (pos == -1) {
                        return L"";
                    }
                }
            }
        }
        return filePath.substr(0, pos);
    }


    static uint64_t GetFileSize(const std::wstring& filePath) {
        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            return 0;
        }
        LARGE_INTEGER li{ 0 };
        ::GetFileSizeEx(hFile, &li);
        CloseHandle(hFile);
        return li.QuadPart;
    }

    static FILETIME GetFileLastWriteTime(const std::wstring& filePath) {
        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            return FILETIME{ 0 };
        }
        FILETIME fileTime;
        ::GetFileTime(hFile, NULL, NULL, &fileTime);
        CloseHandle(hFile);
        return fileTime;
    }


    static bool CopyFolder(const std::wstring& pstrFolder, const std::wstring& pstrDest) {
        /* 检查输入目录是否是合法目录 */
        if (!IsDirectory(pstrFolder)) {
            return false;
        }
        if (!IsDirectory(pstrDest)) {
            CreateDirectoryW(pstrDest.c_str(), NULL);
        }

        std::wstring strFind = pstrFolder;
        if (*strFind.rbegin() != L'\\' &&
            *strFind.rbegin() != L'/') {
            strFind.append(L"\\");
        }
        strFind.append(L"*.*");
        std::wstring strDest = pstrDest;
        if (*strDest.rbegin() != L'\\' &&
            *strDest.rbegin() != L'/') {
            strDest.append(L"\\");
        }

        /* 打开文件查找，查看源目录中是否存在匹配的文件 */
        /* 调用FindFile后，必须调用FindNextFile才能获得查找文件的信息 */
        WIN32_FIND_DATAW wfd;
        HANDLE hFind = FindFirstFileW(strFind.c_str(), &wfd);
        if (hFind == INVALID_HANDLE_VALUE) {
            return false;
        }
        do {
            std::wstring strSubFolder;
            std::wstring strDestFolder;
            if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (wfd.cFileName[0] == L'.') {
                    continue;
                }
                else {
                    strSubFolder = strFind.substr(0, strFind.length() - 3) + wfd.cFileName;
                    strDestFolder = strDest + +wfd.cFileName;
                    CopyFolder(strSubFolder, strDestFolder);
                }
            }
            else {
                strSubFolder = strFind.substr(0, strFind.length() - 3) + wfd.cFileName;
                strDestFolder = strDest + +wfd.cFileName;
                CopyFileW(strSubFolder.c_str(), strDestFolder.c_str(), FALSE);
            }
        } while (FindNextFileW(hFind, &wfd));

        /* 删除空目录 */
        FindClose(hFind);
        return true;
    }

    /* 删除目录及目录中的所有内容 */
    static bool DeleteFolder(const std::wstring& pstrFolder, bool recursive) {
        /* 检查输入目录是否是合法目录 */
        if (!IsDirectory(pstrFolder)) {
            return false;
        }

        std::wstring strFind = pstrFolder;
        if (*strFind.rbegin() != L'\\' &&
            *strFind.rbegin() != L'/') {
            strFind.append(L"\\");
        }
        strFind.append(L"*.*");

        /* 打开文件查找，查看源目录中是否存在匹配的文件 */
        /* 调用FindFile后，必须调用FindNextFile才能获得查找文件的信息 */
        WIN32_FIND_DATAW wfd;
        HANDLE hFind = FindFirstFileW(strFind.c_str(), &wfd);
        if (hFind == INVALID_HANDLE_VALUE) {
            return false;
        }
        do {
            std::wstring strSubFolder;
            if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (wfd.cFileName[0] == L'.') {
                    continue;
                }
                else if (recursive) {
                    strSubFolder = strFind.substr(0, strFind.length() - 3) + wfd.cFileName;
                    DeleteFolder(strSubFolder, recursive);
                }
            }
            else {
                strSubFolder = strFind.substr(0, strFind.length() - 3) + wfd.cFileName;
                DeleteFileW(strSubFolder.c_str());
            }
        } while (FindNextFileW(hFind, &wfd));

        /* 删除空目录 */
        FindClose(hFind);
        return RemoveDirectoryW(pstrFolder.c_str()) == TRUE;
    }

    static std::vector<uint8_t> ReadFile(const wchar_t* pFilePath, size_t size = -1) {
        FILE* fp = NULL;
        errno_t err = _wfopen_s(&fp, pFilePath, L"rb");
        std::vector<uint8_t> buf;
        if (fp) {
            if (size == -1) {
                fseek(fp, 0L, SEEK_END);
                size = ftell(fp);
                fseek(fp, 0, SEEK_SET);
            }
            buf.resize(size);
            if (fread(buf.data(), 1, size, fp) != size) {
                buf.clear();
            }
            fclose(fp);
        }
        return buf;
    }

    static bool WriteFile(const wchar_t* pFilePath, const uint8_t* lpBuff, int nLen, const wchar_t* mode = L"wb") {
        bool bRet = false;
        FILE* fp = NULL;
        errno_t err = _wfopen_s(&fp, pFilePath, mode);
        if (fp) {
            bRet = fwrite(lpBuff, 1, nLen, fp) == nLen;
            fclose(fp);
        }
        return bRet;
    }

private:
    GEEK_STD fstream fs_;
};

} // namespace Geek

#endif // GEEK_FILE_FILE_H_