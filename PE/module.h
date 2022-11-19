#ifndef GEEK_PE_MODULE_H_
#define GEEK_PE_MODULE_H_

#include <string>
#include <vector>

#include <Windows.h>

#include <File/file.h>

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
		offset += sizeof(mDosHeader);

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

	uint64_t GetExportAddress(const std::string exportName) {

	}

private:
#define GET_OPTIONAL_HEADER_FIELD(field, var) \
	{ if (mNtHeader->OptionalHeader.Magic == 0x10b) var = mNtHeader->OptionalHeader.##field; \
	else if (mNtHeader->OptionalHeader.Magic == 0x20b) var = ((IMAGE_NT_HEADERS64*)mNtHeader)->OptionalHeader.##field; \
	else var = 0; } 

	inline uint32_t NarrowAlignment(uint32_t val, uint32_t alignval) noexcept {
		return val - val % alignval;
	}

	inline uint32_t ExpandedAlignment(uint32_t val, uint32_t alignval) noexcept {
		return val - val % alignval + alignval;
	}

	int GetSectionIndexFromRVA(uint32_t rva) {
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

	int GetSectionIndexFromRAW(uint32_t raw) {
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

	uint32_t RVAToRAW(uint32_t rva) {
		auto i = GetSectionIndexFromRVA(rva);
		return rva - mSectionHeaderTable[i].VirtualAddress + mSectionHeaderTable[i].PointerToRawData;
	}

	uint32_t RAWToRVA(uint32_t raw) {
		auto i = GetSectionIndexFromRAW(raw);
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

private:
	IMAGE_DOS_HEADER mDosHeader;
	std::vector<char> mDosStub;
	IMAGE_NT_HEADERS32* mNtHeader;
	IMAGE_FILE_HEADER* mFileHeader;
	std::vector<IMAGE_SECTION_HEADER> mSectionHeaderTable;
	std::vector<std::vector<char>> mSectionList;
};

} // namespace geek

#endif // GEEK_PE_MODULE_H_