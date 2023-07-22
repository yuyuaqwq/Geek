#ifndef GEEK_PE_IMAGE_H_
#define GEEK_PE_IMAGE_H_

#include <string>
#include <vector>

#ifndef WINNT
#include <Windows.h>
#else
#include <ntimage.h>
#endif

#include <geek/file/file.hpp>

/*
* ���ִ���ο���Ŀ��MemoryModule
*/

namespace geek {

#define GET_OPTIONAL_HEADER_FIELD(field, var) \
  { if (m_nt_header->OptionalHeader.Magic == 0x10b) var = m_nt_header->OptionalHeader.##field; \
  else /* (m_nt_header->OptionalHeader.Magic == 0x20b)*/ var = ((IMAGE_NT_HEADERS64*)m_nt_header)->OptionalHeader.##field; } 
#define SET_OPTIONAL_HEADER_FIELD(field, var) \
  { if (m_nt_header->OptionalHeader.Magic == 0x10b) m_nt_header->OptionalHeader.##field = var; \
  else/* (m_nt_header->OptionalHeader.Magic == 0x20b)*/ ((IMAGE_NT_HEADERS64*)m_nt_header)->OptionalHeader.##field = var; } 

class Image {
public:
  typedef uint64_t (*LoadLibraryFunc)(void* process, const char* lib_name);

public:
  Image() : m_dos_header{ 0 }, m_nt_header { nullptr }, m_file_header{ nullptr } {
    
  }

  ~Image() {
    if (m_nt_header) {
      if (m_nt_header->OptionalHeader.Magic == 0x10b) {
        delete m_nt_header;
      }
      else {
        delete (IMAGE_NT_HEADERS64*)m_nt_header;
      }
    }
    
  }


public:
  bool LoadFromImageBuf(void* buf_) {
    IMAGE_SECTION_HEADER* sectionHeaderTable;
    if (!CopyPEHeader(buf_, &sectionHeaderTable)) {
      return false;
    }
    auto buf = (char*)buf_;
    m_memory_image_base = buf;
    m_section_header_table.resize(m_file_header->NumberOfSections);
    m_section_list.resize(m_file_header->NumberOfSections);
    // ���������ͷ����
    for (int i = 0; i < m_file_header->NumberOfSections; i++) {
      m_section_header_table[i] = sectionHeaderTable[i];
      auto virtual_size = max(m_section_header_table[i].Misc.VirtualSize, m_section_header_table[i].SizeOfRawData);
      uint32_t SectionAlignment;
      GET_OPTIONAL_HEADER_FIELD(SectionAlignment, SectionAlignment);
      
      if (virtual_size % SectionAlignment) {
        virtual_size += SectionAlignment - virtual_size % SectionAlignment;
      }
      m_section_list[i].resize(virtual_size, 0);
      memcpy(m_section_list[i].data(), &buf[m_section_header_table[i].VirtualAddress], virtual_size);
    }
    return true;
  }

  bool LoadFromFileBuf(void* buf_) {
    IMAGE_SECTION_HEADER* sectionHeaderTable;
    if (!CopyPEHeader(buf_, &sectionHeaderTable)) {
      return false;
    }
    auto buf = (char*)buf_;
    m_memory_image_base = nullptr;
    m_section_header_table.resize(m_file_header->NumberOfSections);
    m_section_list.resize(m_file_header->NumberOfSections);
    // ���������ͷ����
    for (int i = 0; i < m_file_header->NumberOfSections; i++) {
      m_section_header_table[i] = sectionHeaderTable[i];
      auto virtual_size = max(m_section_header_table[i].Misc.VirtualSize, m_section_header_table[i].SizeOfRawData);
      uint32_t SectionAlignment;
      GET_OPTIONAL_HEADER_FIELD(SectionAlignment, SectionAlignment);
      if (virtual_size % SectionAlignment) {
        virtual_size += SectionAlignment - virtual_size % SectionAlignment;
      }

      if (virtual_size == 0) {
        // dll��û�����ݵ����Σ�
        GET_OPTIONAL_HEADER_FIELD(SectionAlignment, virtual_size);
        m_section_list[i].resize(virtual_size, 0);
      }
      else {
        m_section_list[i].resize(virtual_size, 0);
        memcpy(m_section_list[i].data(), &buf[m_section_header_table[i].PointerToRawData], m_section_header_table[i].SizeOfRawData);
      }
    }
    m_memory_image_base = NULL;
    return true;
  }

  bool LoadFromFile(const std::wstring& path) {
    File pe(path, std::ios::in | std::ios::binary);
    if (!pe.Ok()) {
      return false;
    }
    auto buf = pe.Read();
    return LoadFromFileBuf(buf.data());
  }

  bool SaveToFile(const std::wstring& path) {
    File pe(path, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!pe.Ok()) {
      return false;
    }

    auto buf = SaveToFileBuf();

    return pe.Write(buf);
  }

  std::vector<uint8_t> SaveToFileBuf() {
    std::vector<uint8_t> buf(GetFileSize(), 0);
    int offset = 0;

    memcpy(&buf[offset], &m_dos_header, sizeof(m_dos_header));
    offset += sizeof(m_dos_header);

    memcpy(&buf[offset], m_dos_stub.data(), m_dos_stub.size());
    offset += m_dos_stub.size();

    offset = m_dos_header.e_lfanew;

    if (m_nt_header->OptionalHeader.Magic == 0x10b) {
      memcpy(&buf[offset], m_nt_header, sizeof(*m_nt_header));
      offset += sizeof(*m_nt_header);
    }
    else {
      memcpy(&buf[offset], m_nt_header, sizeof(IMAGE_NT_HEADERS64));
      offset += sizeof(IMAGE_NT_HEADERS64);
    }

    for (int i = 0; i < m_file_header->NumberOfSections; i++) {
      memcpy(&buf[offset], &m_section_header_table[i], sizeof(m_section_header_table[i]));
      offset += sizeof(m_section_header_table[i]);
    }

    for (int i = 0; i < m_file_header->NumberOfSections; i++) {
      memcpy(&buf[m_section_header_table[i].PointerToRawData], m_section_list[i].data(), m_section_header_table[i].SizeOfRawData);
    }
    return buf;
  }

  void SaveToImageBuf(uint8_t* save_buf = nullptr, uint64_t image_base = 0, bool zero_pe_header = false) {
    int offset = 0;
    if (zero_pe_header == false) {
      memcpy(&save_buf[offset], &m_dos_header, sizeof(m_dos_header));
      offset += sizeof(m_dos_header);

      memcpy(&save_buf[offset], m_dos_stub.data(), m_dos_stub.size());
      offset += m_dos_stub.size();

      offset = m_dos_header.e_lfanew;
      if (image_base == 0) {
        image_base = (uint64_t)save_buf;
      }
      uint64_t old_image_base = GetImageBase();
      SetImageBase(image_base);
      if (m_nt_header->OptionalHeader.Magic == 0x10b) {
        memcpy(&save_buf[offset], m_nt_header, sizeof(*m_nt_header));
        offset += sizeof(*m_nt_header);
      }
      else {
        memcpy(&save_buf[offset], m_nt_header, sizeof(IMAGE_NT_HEADERS64));
        offset += sizeof(IMAGE_NT_HEADERS64);
      }
      SetImageBase(old_image_base);

      for (int i = 0; i < m_file_header->NumberOfSections; i++) {
        memcpy(&save_buf[offset], &m_section_header_table[i], sizeof(m_section_header_table[i]));
        offset += sizeof(m_section_header_table[i]);
      }
    }
    for (int i = 0; i < m_file_header->NumberOfSections; i++) {
      memcpy(&save_buf[m_section_header_table[i].VirtualAddress], m_section_list[i].data(), m_section_header_table[i].SizeOfRawData);
    }
  }

  std::vector<uint8_t> SaveToImageBuf(uint64_t image_base = 0, bool zero_pe_header = false) {
    std::vector<uint8_t> buf(GetImageSize(), 0);
    SaveToImageBuf(buf.data(), image_base, zero_pe_header);
    return buf;
  }

  /*
  * field
  */
  bool IsPE32() {
    return m_nt_header->OptionalHeader.Magic == 0x10b;
  }

  uint32_t GetFileSize() {
    int sum = GetPEHeaderSize();
    for (int i = 0; i < m_file_header->NumberOfSections; i++) {
      sum += m_section_header_table[i].SizeOfRawData;
    }
    return sum;
  }

  uint32_t GetImageSize() {
    uint32_t headerSize;
    GET_OPTIONAL_HEADER_FIELD(SizeOfImage, headerSize);
    return headerSize;
  }

  uint32_t GetPEHeaderSize() {
    uint32_t headerSize;
    GET_OPTIONAL_HEADER_FIELD(SizeOfHeaders, headerSize);
    return headerSize;
  }

  uint64_t GetImageBase() {
    uint64_t imageBase;
    GET_OPTIONAL_HEADER_FIELD(ImageBase, imageBase);
    return imageBase;
  }

  void SetImageBase(uint64_t imageBase) {
    SET_OPTIONAL_HEADER_FIELD(ImageBase, imageBase);
  }

  uint32_t GetEntryPoint() {
    uint32_t entry_point;
    GET_OPTIONAL_HEADER_FIELD(AddressOfEntryPoint, entry_point);
    return entry_point;
  }

  void SetEntryPoint(uint32_t entry_point) {
    SET_OPTIONAL_HEADER_FIELD(AddressOfEntryPoint, entry_point);
  }

  IMAGE_DATA_DIRECTORY* GetDataDirectory() {
    IMAGE_DATA_DIRECTORY* dataDirectory;
    GET_OPTIONAL_HEADER_FIELD(DataDirectory, dataDirectory);
    return dataDirectory;
  }

  void* RVAToPoint(uint32_t rva) {
    auto i = GetSectionIndexByRVA(rva);
    if (i == -1) {
      return nullptr;
    }
    return &m_section_list[i][rva - m_section_header_table[i].VirtualAddress];
  }

  /*
  * library
  */
  void* GetExportProcAddress(LoadLibraryFunc load_library, void* process, const char* func_name) {
    uint32_t export_rva;
    if ((uintptr_t)func_name <= 0xffff) {
      export_rva = GetExportRVAByOrdinal((uint16_t)func_name);
    }
    else {
      export_rva = GetExportRVAByName(func_name);
    }
    // ���ܷ���һ���ַ�������Ҫ���μ���
    // ��Ӧ.def�ļ���EXPORTS����� MsgBox = user32.MessageBoxA �����
    uintptr_t va = (uintptr_t)m_memory_image_base + export_rva;
    auto export_directory = (uintptr_t)m_memory_image_base + GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    auto export_directory_size = GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    // ���ڵ�������Χ�ڣ��������ӵ��ַ�����NTDLL.RtlAllocateHeap
    if (va > export_directory && va < export_directory + export_directory_size) {
      std::string full_name = (char*)va;
      auto offset = full_name.find(".");
      auto dll_name = full_name.substr(0, offset);
      auto func_name = full_name.substr(offset + 1);
      if (!dll_name.empty() && !func_name.empty()) {
        auto image_base = load_library(process, dll_name.c_str());
        Image import_image;
        import_image.LoadFromImageBuf((void*)image_base);
        va = (uintptr_t)import_image.GetExportProcAddress(load_library, process, func_name.c_str());
      }
    }
    return (void*)va;
  }

  /*
  * RepositionTable
  */
  bool RepairRepositionTable(uint64_t newImageBase) {
    auto relocationTable = (IMAGE_BASE_RELOCATION*)RVAToPoint(GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    if (relocationTable == nullptr) {
      return false;
    }
    auto imageBase = GetImageBase();
    do {
      auto blockRVA = relocationTable->VirtualAddress;
      auto blockSize = relocationTable->SizeOfBlock;
      if (blockRVA == 0 && blockSize == 0) {
        break;
      }
      uint16_t* fieldTable = (uint16_t*)((char*)relocationTable + sizeof(*relocationTable));
      relocationTable  = (IMAGE_BASE_RELOCATION*)((char*)relocationTable + blockSize);
      auto fieldCount = (blockSize - sizeof(*relocationTable)) / sizeof(*fieldTable);
      for (int i = 0; i < fieldCount; i++) {
        auto offsetType = fieldTable[i] >> 12;
        if (offsetType == IMAGE_REL_BASED_ABSOLUTE) {
          continue;
        }
        auto RVA = blockRVA + (fieldTable[i] & 0xfff);
        if (offsetType == IMAGE_REL_BASED_HIGHLOW) {
          auto addr = (uint32_t*)RVAToPoint(RVA);
          *addr = *addr - imageBase + newImageBase;
        }
        else if (offsetType == IMAGE_REL_BASED_DIR64) {
          auto addr = (uint64_t*)RVAToPoint(RVA);
          *addr = *addr - imageBase + newImageBase;
        }
      }
    } while (true);
    SetImageBase(newImageBase);
    return true;
  }

  /*
  * ExportTable
  */
  uint32_t GetExportRVAByName(const std::string& func_name) {
    auto exportDirectory = (IMAGE_EXPORT_DIRECTORY*)RVAToPoint(GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (exportDirectory == nullptr) {
      return 0;
    }
    auto numberOfNames = exportDirectory->NumberOfNames;
    auto addressOfNames = (uint32_t*)RVAToPoint(exportDirectory->AddressOfNames);
    auto addressOfNameOrdinals = (uint16_t*)RVAToPoint(exportDirectory->AddressOfNameOrdinals);
    auto addressOfFunctions = (uint32_t*)RVAToPoint(exportDirectory->AddressOfFunctions);
    int funcIdx = -1;
    for (int i = 0; i < numberOfNames; i++) {
      auto exportName = (char*)RVAToPoint(addressOfNames[i]);
      if (func_name == exportName) {
        // ͨ�����±������ű����õ�����AddressOfFunctions���±�
        funcIdx = addressOfNameOrdinals[i];
      }
    }
    if (funcIdx == -1) {
      return 0;
    }
    return addressOfFunctions[funcIdx];
  }

  uint32_t GetExportRVAByOrdinal(uint16_t ordinal) {
    auto exportDirectory = (IMAGE_EXPORT_DIRECTORY*)RVAToPoint(GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (exportDirectory == nullptr) {
      return 0;
    }
    auto addressOfFunctions = (uint32_t*)RVAToPoint(exportDirectory->AddressOfFunctions);
    // �ⲿ�ṩ��ordinal��Ҫ��ȥbase
    auto funcIdx = ordinal - exportDirectory->Base;
    return addressOfFunctions[funcIdx];
  }

  /*
  * ImportTable
  */


  /* ImportAddressTable */
private:
  template<typename IMAGE_THUNK_DATA_T>
  void** GetImportAddressPointByNameFromDll(_IMAGE_IMPORT_DESCRIPTOR* import_descriptor, const char* lib_name, const char* func_name) {
    IMAGE_THUNK_DATA_T* import_name_table = (IMAGE_THUNK_DATA_T*)RVAToPoint(import_descriptor->OriginalFirstThunk);
    IMAGE_THUNK_DATA_T* import_address_table = (IMAGE_THUNK_DATA_T*)RVAToPoint(import_descriptor->FirstThunk);
    for (; import_name_table->u1.ForwarderString; import_name_table++, import_address_table++) {
      if (import_name_table->u1.Ordinal >> (sizeof(import_name_table->u1.Ordinal) * 8 - 1) == 1) {
        continue;
      }
      else {
        IMAGE_IMPORT_BY_NAME* cur_func_name = (IMAGE_IMPORT_BY_NAME*)RVAToPoint(import_name_table->u1.AddressOfData);
        if (std::string((char*)cur_func_name->Name) == func_name) {
          return (void**)&import_address_table->u1.Function;
        }
      }
    }
    return nullptr;
  }
  template<typename IMAGE_THUNK_DATA_T>
  void** GetImportAddressPointByAddressFromDll(_IMAGE_IMPORT_DESCRIPTOR* import_descriptor, void* address) {
    IMAGE_THUNK_DATA_T* import_name_table = (IMAGE_THUNK_DATA_T*)RVAToPoint(import_descriptor->OriginalFirstThunk);
    IMAGE_THUNK_DATA_T* import_address_table = (IMAGE_THUNK_DATA_T*)RVAToPoint(import_descriptor->FirstThunk);
    for (; import_name_table->u1.Function; import_name_table++, import_address_table++) {
      if ((void*)import_address_table->u1.Function == address) {
        auto offset = VaToOffset(&import_address_table->u1.Function);
        if (offset == 0) return nullptr;
        return (void**)((uintptr_t)m_memory_image_base + offset);
      }
    }
    return nullptr;
  }
public:
  void** GetImportAddressPointByName(const char* lib_name, const char* func_name) {
    if (!m_memory_image_base) return nullptr;
    auto import_descriptor = (_IMAGE_IMPORT_DESCRIPTOR*)RVAToPoint(GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    for (; import_descriptor->OriginalFirstThunk && import_descriptor->FirstThunk; import_descriptor++) {
      char* import_module_name = (char*)RVAToPoint(import_descriptor->Name);
      if (import_module_name != lib_name) {
        continue;
      }
      if (IsPE32()) {
        return GetImportAddressPointByNameFromDll<IMAGE_THUNK_DATA32>(import_descriptor, lib_name, func_name);
      } else {
        return GetImportAddressPointByNameFromDll<IMAGE_THUNK_DATA64>(import_descriptor, lib_name, func_name);
      }
    }
  }
  void** GetImportAddressPointByAddr(void* address) {
    if (!m_memory_image_base) return nullptr;
    auto import_descriptor = (_IMAGE_IMPORT_DESCRIPTOR*)RVAToPoint(GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    for (; import_descriptor->OriginalFirstThunk && import_descriptor->FirstThunk; import_descriptor++) {
      if (IsPE32()) {
        return GetImportAddressPointByAddressFromDll<IMAGE_THUNK_DATA32>(import_descriptor, address);
      } else {
        return GetImportAddressPointByAddressFromDll<IMAGE_THUNK_DATA64>(import_descriptor, address);
      }
    }
    return nullptr;
  }

private:
  template<typename IMAGE_THUNK_DATA_T>
  bool RepairImportAddressTableFromDll(LoadLibraryFunc load_library, void* process, _IMAGE_IMPORT_DESCRIPTOR* import_descriptor, void* import_image_base, bool skip_not_loaded) {
    IMAGE_THUNK_DATA_T* import_name_table = (IMAGE_THUNK_DATA_T*)RVAToPoint(import_descriptor->OriginalFirstThunk);
    IMAGE_THUNK_DATA_T* import_address_table = (IMAGE_THUNK_DATA_T*)RVAToPoint(import_descriptor->FirstThunk);
    Image import_image;
    if (import_image_base) {
      if (!import_image.LoadFromImageBuf((void*)import_image_base)) {
        return false;
      }
    }
    else if (!skip_not_loaded) {
      return false;
    }
    for (; import_name_table->u1.ForwarderString; import_name_table++, import_address_table++) {
      if (!import_image_base) {
        import_address_table->u1.Function = import_address_table->u1.Function = 0x1234567887654321;
        continue;
      }
      uint32_t export_rva;
      if (import_name_table->u1.Ordinal >> (sizeof(import_name_table->u1.Ordinal) * 8 - 1) == 1) {
        import_address_table->u1.Function = (uintptr_t)import_image.GetExportProcAddress(load_library, process, (char*)((import_name_table->u1.Ordinal << 1) >> 1));
      }
      else {
        IMAGE_IMPORT_BY_NAME* func_name = (IMAGE_IMPORT_BY_NAME*)RVAToPoint(import_name_table->u1.AddressOfData);
        import_address_table->u1.Function = (uintptr_t)import_image.GetExportProcAddress(load_library, process, (char*)func_name->Name);
      }
      //import_address_table->u1.Function = import_module_base + export_rva;
    }
    return true;
  }
public:
  bool RepairImportAddressTable(LoadLibraryFunc load_library, void* process, bool skip_not_loaded = false) {
    auto import_descriptor = (_IMAGE_IMPORT_DESCRIPTOR*)RVAToPoint(GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    if (import_descriptor == nullptr) {
      return false;
    }
    for (; import_descriptor->OriginalFirstThunk && import_descriptor->FirstThunk; import_descriptor++) {
      char* import_module_name = (char*)RVAToPoint(import_descriptor->Name);
      void* import_module_base = (void*)load_library(process, import_module_name);
      if (IsPE32()) {
        if (!RepairImportAddressTableFromDll<IMAGE_THUNK_DATA32>(load_library, process, import_descriptor, import_module_base, skip_not_loaded)) {
          return false;
        }
      }
      else {
        if (!RepairImportAddressTableFromDll<IMAGE_THUNK_DATA64>(load_library, process, import_descriptor, import_module_base, skip_not_loaded)) {
          return false;
        }
      }
    }
    return true;
  }

  /*
  * TLS
  */
private:
  // PIMAGE_TLS_CALLBACK
  typedef VOID (NTAPI* PIMAGE_TLS_CALLBACK32)(uint32_t DllHandle, DWORD Reason, PVOID Reserved);
  typedef VOID(NTAPI* PIMAGE_TLS_CALLBACK64)(uint64_t DllHandle, DWORD Reason, PVOID Reserved);
public:
  bool ExecuteTls(uint64_t ImageBase) {
    auto tls_dir = (IMAGE_TLS_DIRECTORY*)RVAToPoint(GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
    if (tls_dir == nullptr) {
      return false;
    }
    PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)tls_dir->AddressOfCallBacks;
    if (callback) {
      while (*callback) {
        if (IsPE32()) {
          PIMAGE_TLS_CALLBACK32 callback32 = *(PIMAGE_TLS_CALLBACK32*)callback;
          callback32((uint32_t)ImageBase, DLL_PROCESS_ATTACH, NULL);
        }
        else {
          PIMAGE_TLS_CALLBACK64 callback64 = *(PIMAGE_TLS_CALLBACK64*)callback;
          callback64(ImageBase, DLL_PROCESS_ATTACH, NULL);
        }
        callback++;
      }
    }
    return true;
  }

  /*
  * Running
  */
private:
  typedef BOOL(WINAPI* DllEntryProc32)(uint32_t hinstDLL, DWORD fdwReason, uint32_t lpReserved);
  typedef BOOL(WINAPI* DllEntryProc64)(uint64_t hinstDLL, DWORD fdwReason, uint64_t lpReserved);
  typedef int (WINAPI* ExeEntryProc)(void);
public:
  void CallEntryPoint(uint64_t ImageBase, uint64_t init_parameter = 0) {
    uint32_t rva = GetEntryPoint();
    if (m_file_header->Characteristics & IMAGE_FILE_DLL) {
      if (IsPE32()) {
        DllEntryProc32 DllEntry = (DllEntryProc32)(ImageBase + rva);
        DllEntry((uint32_t)ImageBase, DLL_PROCESS_ATTACH, (uint32_t)init_parameter);
      }
      else {
        DllEntryProc64 DllEntry = (DllEntryProc64)(ImageBase + rva);
        DllEntry(ImageBase, DLL_PROCESS_ATTACH, init_parameter);
      }
    }
    else {
      ExeEntryProc ExeEntry = (ExeEntryProc)(LPVOID)(ImageBase + rva);
      // exe��ִ��
    }
  }

  /*
  * CheckSum
  */
private:
  // https://www.likecs.com/show-306676949.html
  uint32_t calc_checksum(uint32_t checksum, const void* data, int length) {
    if (length && data != nullptr) {
      uint32_t sum = 0;
      do {
        sum = *(uint16_t*)data + checksum;
        checksum = (uint16_t)sum + (sum >> 16);
        data = (char*)data + 2;
      } while (--length);
    }
    return checksum + (checksum >> 16);
  }
  uint32_t generate_pe_checksum(const void* file_base, uint32_t file_size) {
    uint32_t file_checksum = 0;
    if (m_nt_header) {
      file_checksum = calc_checksum(0, file_base, file_size >> 1);
      if (file_size & 1) {
        file_checksum += (uint16_t) * ((char*)file_base + file_size - 1);
      }
    }
    return (file_size + file_checksum);
  }
public:
  bool CheckSum() {
    uint32_t old_check_sum;
    GET_OPTIONAL_HEADER_FIELD(CheckSum, old_check_sum);
    SET_OPTIONAL_HEADER_FIELD(CheckSum, 0);
    auto buf = SaveToFileBuf();
    uint32_t check_sum = generate_pe_checksum(buf.data(), buf.size());
    SET_OPTIONAL_HEADER_FIELD(CheckSum, old_check_sum);

    return old_check_sum == check_sum;
  }

  void RepairCheckSum() {
    // https://blog.csdn.net/iiprogram/article/details/1585940/
    SET_OPTIONAL_HEADER_FIELD(CheckSum, 0);
    auto buf = SaveToFileBuf();
    uint32_t check_sum = generate_pe_checksum(buf.data(), buf.size());
    SET_OPTIONAL_HEADER_FIELD(CheckSum, check_sum);
  }

  /*
  * Signature
  */
  bool CheckDigitalSignature() {

  }

  std::vector<uint8_t> CalculationAuthHashCalc() {

  }

  /*
  * Resource
  */
  static std::vector<uint8_t> GetResource(HMODULE handle_module, DWORD resource_id, LPCWSTR type) {
    //������Դ
    std::vector<uint8_t> buf;
    HGLOBAL hRes = NULL;
    do {
      HRSRC hResID = FindResourceW(handle_module, MAKEINTRESOURCEW(resource_id), type);
      if (!hResID) {
        break;
      }
      //������Դ  
      hRes = LoadResource(handle_module, hResID);
      if (!hRes) {
        break;
      }
      //������Դ
      LPVOID pRes = LockResource(hRes);
      if (pRes == NULL) {
        break;
      }
      DWORD dwResSize = SizeofResource(handle_module, hResID);
      buf.resize(dwResSize);
      memcpy(buf.data(), pRes, dwResSize);
    } while (false);

    if (hRes) {
      UnlockResource(hRes);
      FreeResource(hRes);
      hRes = NULL;
    }
    return buf;
  }

private:

  bool CopyPEHeader(void* buf_, IMAGE_SECTION_HEADER** sectionHeaderTable) {
    auto buf = (char*)buf_;
    m_dos_header = *(IMAGE_DOS_HEADER*)buf;
    if (m_dos_header.e_magic != 'ZM') {    // 'MZ'
      return false;
    }
    auto dosStubSize = m_dos_header.e_lfanew - sizeof(m_dos_header);
    if (dosStubSize < 0) {
      dosStubSize = 0;
    }
    m_dos_stub.resize(dosStubSize, 0);
    memcpy(m_dos_stub.data(), &buf[sizeof(m_dos_header)], dosStubSize);

    auto ntHeader = (IMAGE_NT_HEADERS32*)&buf[m_dos_header.e_lfanew];
    if (ntHeader->Signature != 'EP') {    // 'PE'
      return false;
    }

    // ����PEͷ
    auto optionalHeader32 = &ntHeader->OptionalHeader;
    if (optionalHeader32->Magic == 0x10b) {
      m_nt_header = new IMAGE_NT_HEADERS32;
      *m_nt_header = *ntHeader;
    }
    else if (optionalHeader32->Magic == 0x20b) {
      m_nt_header = (IMAGE_NT_HEADERS32*)new IMAGE_NT_HEADERS64;
      *(IMAGE_NT_HEADERS64*)m_nt_header = *(IMAGE_NT_HEADERS64*)ntHeader;
    }
    else {
      return false;
    }

    m_file_header = &m_nt_header->FileHeader;

    auto optionalHeader = &m_nt_header->OptionalHeader;
    if (optionalHeader->Magic == 0x10b) {
      *sectionHeaderTable = (IMAGE_SECTION_HEADER*)(ntHeader + 1);
    }
    else {
      *sectionHeaderTable = (IMAGE_SECTION_HEADER*)((IMAGE_NT_HEADERS64*)ntHeader + 1);
    }
    return true;
  }

  inline uint32_t NarrowAlignment(uint32_t val, uint32_t alignval) noexcept {
    return val - val % alignval;
  }

  inline uint32_t ExpandedAlignment(uint32_t val, uint32_t alignval) noexcept {
    return val - val % alignval + alignval;
  }

  int GetSectionIndexByRVA(uint32_t rva) {
    int i = 0;
    for (; i < m_file_header->NumberOfSections; i++) {
      if (rva < m_section_header_table[i].VirtualAddress) {
        return i - 1;
      }
    }

    i--;
    // ����λ�����һ��������������Խ��
    if (rva - m_section_header_table[i].VirtualAddress > m_section_header_table[i].SizeOfRawData) {
      return -1;
    }

    return i;
  }

  int GetSectionIndexByRAW(uint32_t raw) {
    int i = 0;
    for (; i < m_file_header->NumberOfSections; i++) {
      if (raw < m_section_header_table[i].PointerToRawData) {
        return i - 1;
      }
    }

    i--;
    // ����λ�����һ��������������Խ��
    if (raw - m_section_header_table[i].PointerToRawData + 1 > m_section_header_table[i].SizeOfRawData) {
      return -1;
    }

    return i;
  }

  uint32_t VaToOffset(void* va) {
    for (int i = 0; i < m_file_header->NumberOfSections; i++) {
      auto addr = &m_section_list[i][0];
      if ((uint8_t*)va >= addr && (uint8_t*)va < &m_section_list[i][m_section_list[i].size()]) {
        return m_section_header_table[i].VirtualAddress + ((uintptr_t)va - (uintptr_t)m_section_list[i].data());
      }
    }
    return 0;
  }

  uint32_t RvaToRaw(uint32_t rva) {
    auto i = GetSectionIndexByRVA(rva);
    if (i == -1) {
      return 0;
    }
    return rva - m_section_header_table[i].VirtualAddress + m_section_header_table[i].PointerToRawData;
  }

  uint32_t RawToRva(uint32_t raw) {
    auto i = GetSectionIndexByRAW(raw);
    if (i == -1) {
      return 0;
    }
    return raw - m_section_header_table[i].PointerToRawData + m_section_header_table[i].VirtualAddress;
  }

private:
  IMAGE_DOS_HEADER m_dos_header;
  std::vector<uint8_t> m_dos_stub;
  IMAGE_NT_HEADERS32* m_nt_header;
  IMAGE_FILE_HEADER* m_file_header;
  std::vector<IMAGE_SECTION_HEADER> m_section_header_table;
  std::vector<std::vector<uint8_t>> m_section_list;

  void* m_memory_image_base;
};

} // namespace geek

#endif // GEEK_PE_IMAGE_H_