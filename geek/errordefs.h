#pragma once

namespace geek {
namespace internal {
void UpdateWinError(const char* w);
void UpdateNtError(uint32_t e, const char* w);
}
}

#define GEEK_UPDATE_WIN_ERROR() geek::internal::UpdateWinError(__FUNCTION__)
#define GEEK_UPDATE_NT_ERROR(e) geek::internal::UpdateNtError(e,__FUNCTION__)