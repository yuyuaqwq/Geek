#include "Handle.h"

namespace geek {

UniqueHandle::UniqueHandle(HANDLE t_handle) noexcept : m_hanlde{ t_handle } {

}
UniqueHandle::UniqueHandle() noexcept : m_hanlde{ NULL } {

}
UniqueHandle::~UniqueHandle() noexcept {
	Close();
}



UniqueHandle::UniqueHandle(UniqueHandle&& t_uniqueHandle) noexcept {
	*this = std::move(t_uniqueHandle);
}
void UniqueHandle::operator=(UniqueHandle&& t_uniqueHandle) noexcept {
	Close();
	m_hanlde = t_uniqueHandle.m_hanlde;
	t_uniqueHandle.m_hanlde = NULL;
}


inline HANDLE UniqueHandle::Get() const noexcept {
	return m_hanlde;
}
inline bool UniqueHandle::Valid() const noexcept {
	return m_hanlde != NULL &&  m_hanlde!= INVALID_HANDLE_VALUE;
}


inline void UniqueHandle::Close() noexcept {
	if (Valid()) {
		::CloseHandle(m_hanlde);
	}
}

} // namespace geek
