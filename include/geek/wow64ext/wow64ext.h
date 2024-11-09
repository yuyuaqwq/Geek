#pragma once
#include <memory>

#include <Windows.h>

#include <geek/wow64ext/wow64extdefs.h>

/*
* https://github.com/rwfpl/rewolf-Wow64ext
*/

namespace geek {

static HANDLE ms_heap = NULL;
static BOOL ms_is_wow64 = FALSE;

class Wow64 {
public:
    static bool Wow64Operation(HANDLE hProcess);

    Wow64();

    static void* Wow64Malloc(size_t size);
    static void Wow64Free(void* ptr);
    static void __cdecl Wow64ExtInit();
    static DWORD64 __cdecl X64Call(DWORD64 func, int argC, ...);
    static DWORD64 __cdecl GetModuleHandle64(const wchar_t* lpModuleName);
    static void __cdecl SetLastErrorFromX64Call(DWORD64 status);
    static DWORD64 __cdecl GetProcAddress64(DWORD64 hModule, const char* funcName);
    static DWORD64 __cdecl VirtualQueryEx64(HANDLE hProcess, DWORD64 lpAddress, MEMORY_BASIC_INFORMATION64* lpBuffer, SIZE_T dwLength);
    static DWORD64 __cdecl VirtualAllocEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    static BOOL __cdecl VirtualFreeEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD dwFreeType);
    static BOOL __cdecl VirtualProtectEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* lpflOldProtect);
    static BOOL __cdecl ReadProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
    static BOOL __cdecl WriteProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
    static BOOL __cdecl GetThreadContext64(HANDLE hThread, _CONTEXT64* lpContext);
    static BOOL __cdecl SetThreadContext64(HANDLE hThread, _CONTEXT64* lpContext);
    static void GetMem64(void* dstMem, DWORD64 srcMem, size_t sz);
    static bool CmpMem64(const void* dstMem, DWORD64 srcMem, size_t sz);
    static DWORD64 GetTEB64();
    static DWORD64 GetNTDLL64();
    static DWORD64 GetLdrGetProcedureAddress();

private:
    //inline static HANDLE ms_heap = NULL;
    //inline static BOOL ms_is_wow64 = FALSE;
};

}