#ifndef GEEK_PE_IMAGE_HPP_
#define GEEK_PE_IMAGE_HPP_

#include <string>
#include <vector>
#include <optional>

#include <geek/pe/image_section_header_table.h>
#include <geek/pe/image_nt_header.h>

#ifndef WINNT
#include <Windows.h>
#include <geek/utils/file.h>
#else
#include <ntimage.h>
#endif

namespace geek {
class Image {
public:
    Image();
    Image(Image&& other) noexcept;
    Image& operator=(Image&& other) noexcept;
    Image(const Image&) = delete;
    void operator=(const Image&) = delete;
    ~Image();

    static std::optional<Image> LoadFromImageBuf(void* buf, uint64_t memory_image_base);
    static std::optional<Image> LoadFromFileBuf(void* buf, uint64_t memory_image_base);
    static std::optional<Image> LoadFromFile(std::wstring_view path);

    bool ReloadFromImageBuf(void* buf_, uint64_t memory_image_base) const;
    bool ReloadFromFileBuf(void* buf_, uint64_t memory_image_base) const;
    bool ReloadFromFile(std::wstring_view path) const;
    bool SaveToFile(std::wstring_view path) const;
    std::vector<uint8_t> SaveToFileBuf() const;
    void SaveToImageBuf(uint8_t* save_buf = nullptr, uint64_t image_base = 0, bool zero_pe_header = false) const;
    std::vector<uint8_t> SaveToImageBuf(uint64_t image_base = 0, bool zero_pe_header = false) const;

    bool IsPE32() const;
    bool IsDll() const;

    ImageNtHeader NtHeader() const;
	ImageSectionHeaderTable SectionHeaderTable() const;

    uint32_t GetFileSize() const;
    uint64_t GetMemoryImageBase() const;
    void SetMemoryImageBase(uint64_t imageBase) const;
    void* RvaToPoint(uint32_t rva) const;

    bool RepairRepositionTable(uint64_t newImageBase) const;

    // uint32_t GetExportRvaByName(const std::string& func_name) const;
    // uint32_t GetExportRvaByOrdinal(uint16_t ordinal);
    //
    // std::optional<uint32_t> GetImportAddressRawByName(const std::string& lib_name, const std::string& func_name);
    // std::optional<uint32_t> GetImportAddressRawByAddr(void* address);

    bool CheckSum() const;
    void RepairCheckSum() const;

    bool CheckDigitalSignature() { } //TODO CheckDigitalSignature
    std::vector<uint8_t> CalculationAuthHashCalc() { } //TODO CalculationAuthHashCalc

    static std::optional<std::vector<uint8_t>> GetResource(HMODULE handle_module, DWORD resource_id, LPCWSTR type);

private:
    friend class ImageNtHeader;
    friend class ImageSectionHeaderTable;

    class Impl;
    std::unique_ptr<Impl> impl_;

};

} // namespace geek

#endif // GEEK_PE_IMAGE_HPP_