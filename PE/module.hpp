#ifndef GEEK_PE_MODULE_H_
#define GEEK_PE_MODULE_H_

#include <string>
#include <vector>

#include <Windows.h>

#include <Geek/File/file.hpp>

namespace geek {

class Module {
public:
	Module() : mDosHeader{ 0 }, mNtHeader { nullptr }, mFileHeader{ nullptr } {

	}

	~Module() {
		if (mNtHeader) {
			if (mNtHeader->OptionalHeader.Magic == 0x10b) {
				delete mNtHeader;
			}
			else {
				delete (IMAGE_NT_HEADERS64*)mNtHeader;
			}
		}
		
	}


public:
	bool LoadModuleFromFile(const std::wstring& path) {
		File pe(path, std::ios::in | std::ios::binary);
		auto buf = pe.Read();

		mDosHeader = *(IMAGE_DOS_HEADER*)buf.data();
		if (mDosHeader.e_magic != 'ZM') {		// 'MZ'
			return false;
		}
		auto dosStubSize = mDosHeader.e_lfanew - sizeof(mDosHeader);
		if (dosStubSize < 0) {
			dosStubSize = 0;
		}
		mDosStub.resize(dosStubSize, 0);
		memcpy(mDosStub.data(), &buf[sizeof(mDosHeader)], dosStubSize);

		auto ntHeader = (IMAGE_NT_HEADERS32*)&buf[mDosHeader.e_lfanew];
		if (ntHeader->Signature != 'EP') {		// 'PE'
			return false;
		}

		

		// 拷贝PE头
		auto optionalHeader32 = &ntHeader->OptionalHeader;
		if (optionalHeader32->Magic == 0x10b) {
			mNtHeader = new IMAGE_NT_HEADERS32;
			*mNtHeader = *ntHeader;
		}
		else if (optionalHeader32->Magic == 0x20b) {
			mNtHeader = (IMAGE_NT_HEADERS32*)new IMAGE_NT_HEADERS64;
			*(IMAGE_NT_HEADERS64*)mNtHeader = *(IMAGE_NT_HEADERS64*)ntHeader;
		}
		else {
			return false;
		}

		mFileHeader = &mNtHeader->FileHeader;

		auto optionalHeader = &mNtHeader->OptionalHeader;
		IMAGE_SECTION_HEADER* sectionHeaderTable;
		if (optionalHeader->Magic == 0x10b) {
			sectionHeaderTable = (IMAGE_SECTION_HEADER*)(ntHeader + 1);
		}
		else {
			sectionHeaderTable = (IMAGE_SECTION_HEADER*)((IMAGE_NT_HEADERS64*)ntHeader + 1);
		}

		mSectionHeaderTable.resize(mFileHeader->NumberOfSections);
		mSectionList.resize(mFileHeader->NumberOfSections);
		// 保存节区和头节区
		for (int i = 0; i < mFileHeader->NumberOfSections; i++) {
			mSectionHeaderTable[i] = sectionHeaderTable[i];
			mSectionList[i].resize(mSectionHeaderTable[i].SizeOfRawData, 0);
			memcpy(mSectionList[i].data(), &buf[mSectionHeaderTable[i].PointerToRawData], mSectionHeaderTable[i].SizeOfRawData);
		}
		return true;
	}

	bool SaveModuleToFile(const std::wstring& path) {
		File pe(path, std::ios::out | std::ios::binary | std::ios::trunc);

		std::vector<char> buf(GetFileSize(), 0);

		int offset = 0;

		memcpy(&buf[offset], &mDosHeader, sizeof(mDosHeader));
		offset = mDosHeader.e_lfanew;

		memcpy(&buf[offset], mDosStub.data(), mDosStub.size());
		offset += mDosStub.size();

		if (mNtHeader->OptionalHeader.Magic == 0x10b) {
			memcpy(&buf[offset], mNtHeader, sizeof(*mNtHeader));
			offset += sizeof(*mNtHeader);
		}
		else {
			memcpy(&buf[offset], mNtHeader, sizeof(IMAGE_NT_HEADERS64));
			offset += sizeof(IMAGE_NT_HEADERS64);
		}
		
		for (int i = 0; i < mFileHeader->NumberOfSections; i++) {
			memcpy(&buf[offset], &mSectionHeaderTable[i], sizeof(mSectionHeaderTable[i]));
			offset += sizeof(mSectionHeaderTable[i]);
		}

		for (int i = 0; i < mFileHeader->NumberOfSections; i++) {
			memcpy(&buf[mSectionHeaderTable[i].PointerToRawData], mSectionList[i].data(), mSectionHeaderTable[i].SizeOfRawData);
		}

		return pe.Write(buf);
	}

	uint32_t GetExportRVAByName(const std::string& funcName) {
		auto exportDirectory = (IMAGE_EXPORT_DIRECTORY*)RVAToPoint(GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		if (exportDirectory == nullptr) {
			return 0;
		}
		auto numberOfNames = exportDirectory->NumberOfNames;
		auto addressOfNames = (DWORD*)RVAToPoint(exportDirectory->AddressOfNames);
		auto addressOfNameOrdinals = (WORD*)RVAToPoint(exportDirectory->AddressOfNameOrdinals);
		auto addressOfFunctions = (DWORD*)RVAToPoint(exportDirectory->AddressOfFunctions);
		int funcIdx = -1;
		for (int i = 0; i < numberOfNames; i++) {
			auto exportName = (char*)RVAToPoint(addressOfNames[i]);
			if (funcName == exportName) {
				// 通过此下标访问序号表，得到访问AddressOfFunctions的下标
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
		auto addressOfFunctions = (DWORD*)RVAToPoint(exportDirectory->AddressOfFunctions);
		// 外部提供的ordinal需要减去base
		auto funcIdx = ordinal - exportDirectory->Base;
		return addressOfFunctions[funcIdx];
	}

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
			WORD* fieldTable = (WORD*)((char*)relocationTable + sizeof(*relocationTable));
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

				if (offsetType == IMAGE_REL_BASED_DIR64) {
					auto addr = (uint64_t*)RVAToPoint(RVA);
					*addr = *addr - imageBase + newImageBase;
				}

			}
		} while (true);
		
		SetImageBase(newImageBase);
		return true;
	}

	bool CheckDigitalSignature() {

	}


private:
#define GET_OPTIONAL_HEADER_FIELD(field, var) \
	{ if (mNtHeader->OptionalHeader.Magic == 0x10b) var = mNtHeader->OptionalHeader.##field; \
	else if (mNtHeader->OptionalHeader.Magic == 0x20b) var = ((IMAGE_NT_HEADERS64*)mNtHeader)->OptionalHeader.##field; \
	else var = 0; } 
#define SET_OPTIONAL_HEADER_FIELD(field, var) \
	{ if (mNtHeader->OptionalHeader.Magic == 0x10b) mNtHeader->OptionalHeader.##field = var; \
	else if (mNtHeader->OptionalHeader.Magic == 0x20b) ((IMAGE_NT_HEADERS64*)mNtHeader)->OptionalHeader.##field = var; \
	else var = 0; } 

	inline uint32_t NarrowAlignment(uint32_t val, uint32_t alignval) noexcept {
		return val - val % alignval;
	}

	inline uint32_t ExpandedAlignment(uint32_t val, uint32_t alignval) noexcept {
		return val - val % alignval + alignval;
	}

	int GetSectionIndexByRVA(uint32_t rva) {
		int i = 0;
		for (; i < mFileHeader->NumberOfSections; i++) {
			if (rva < mSectionHeaderTable[i].VirtualAddress) {
				return i - 1;
			}
		}

		i--;
		// 可能位于最后一个节区，但不能越界
		if (rva - mSectionHeaderTable[i].VirtualAddress > mSectionHeaderTable[i].SizeOfRawData) {
			return -1;
		}

		return i;
	}

	int GetSectionIndexByRAW(uint32_t raw) {
		int i = 0;
		for (; i < mFileHeader->NumberOfSections; i++) {
			if (raw < mSectionHeaderTable[i].PointerToRawData) {
				return i - 1;
			}
		}

		i--;
		// 可能位于最后一个节区，但不能越界
		if (raw - mSectionHeaderTable[i].PointerToRawData + 1 > mSectionHeaderTable[i].SizeOfRawData) {
			return -1;
		}

		return i;
	}

	void* RVAToPoint(uint32_t rva) {
		auto i = GetSectionIndexByRVA(rva);
		if (i == -1) {
			return nullptr;
		}
		return &mSectionList[i][rva - mSectionHeaderTable[i].VirtualAddress];
	}

	uint32_t RVAToRAW(uint32_t rva) {
		auto i = GetSectionIndexByRVA(rva);
		if (i == -1) {
			return 0;
		}
		return rva - mSectionHeaderTable[i].VirtualAddress + mSectionHeaderTable[i].PointerToRawData;
	}

	uint32_t RAWToRVA(uint32_t raw) {
		auto i = GetSectionIndexByRAW(raw);
		if (i == -1) {
			return 0;
		}
		return raw - mSectionHeaderTable[i].PointerToRawData + mSectionHeaderTable[i].VirtualAddress;
	}

	uint32_t GetFileSize() {
		int sum = GetPEHeaderSize();
		for (int i = 0; i < mFileHeader->NumberOfSections; i++) {
			sum += mSectionHeaderTable[i].SizeOfRawData;
		}
		return sum;
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

	IMAGE_DATA_DIRECTORY* GetDataDirectory() {
		IMAGE_DATA_DIRECTORY* dataDirectory;
		GET_OPTIONAL_HEADER_FIELD(DataDirectory, dataDirectory);
		return dataDirectory;
	}

	std::vector<uint8_t> CalculationAuthHashCalc() {

	}


private:
	IMAGE_DOS_HEADER mDosHeader;
	std::vector<uint8_t> mDosStub;
	IMAGE_NT_HEADERS32* mNtHeader;
	IMAGE_FILE_HEADER* mFileHeader;
	std::vector<IMAGE_SECTION_HEADER> mSectionHeaderTable;
	std::vector<std::vector<uint8_t>> mSectionList;
};

} // namespace geek

#endif // GEEK_PE_MODULE_H_