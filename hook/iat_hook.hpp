#ifndef GEEK_HOOK_IAT_HOOK_H_
#define GEEK_HOOK_IAT_HOOK_H_

#include <string>

#include <Geek/pe/image.hpp>

namespace Geek {

class IatHook {
public:
    bool Install(Geek::Image* image, std::string_view import_lib_name, std::string_view import_func_name, void* new_addr) {
        auto func_addr_ptr_rew = image->GetImportAddressRawByName(import_lib_name.data(), import_func_name.data());
        if (!func_addr_ptr_rew) return false;
        func_addr_raw = *func_addr_ptr_rew;

        memory_image_base = image->GetMemoryImageBase();

        void** func_addr_ptr = (void**)(memory_image_base + func_addr_raw);
        DWORD old_protect;
        CurrentProcess.SetMemoryProtect((uint64_t)func_addr_ptr, sizeof(void*), PAGE_READWRITE, &old_protect);
        original_func_addr_ = *func_addr_ptr;
        *func_addr_ptr = new_addr;
        CurrentProcess.SetMemoryProtect((uint64_t)func_addr_ptr, sizeof(void*), old_protect, &old_protect);
        return true;
    }

    void Uninstall() {
        void** func_addr_ptr = (void**)(memory_image_base + func_addr_raw);
        DWORD old_protect;
        CurrentProcess.SetMemoryProtect((uint64_t)func_addr_ptr, sizeof(void*), PAGE_READWRITE, &old_protect);
        *func_addr_ptr = original_func_addr_;
        CurrentProcess.SetMemoryProtect((uint64_t)func_addr_ptr, sizeof(void*), old_protect, &old_protect);
    }

    void* GetOriginalFuncAddr() {
        return original_func_addr_;
    }

private:
    uint64_t memory_image_base = 0;
    uint32_t func_addr_raw = 0;
    void* original_func_addr_ = nullptr;
};

} // namespace Geek

#endif // GEEK_HOOK_IAT_HOOK_H_
