#pragma once
#include <optional>
#include <vector>

namespace geek {
class Process;

class Address {
public:
	Address(Process* proc, uint64_t addr);

	bool Read(void* buf, size_t len) const;
	std::optional<std::vector<uint8_t>> Read(size_t len) const;
	template<class T>
	std::optional<T> ReadValue(uint64_t addr) const;

	bool Write(const void* buf, size_t len, bool force = false) const;

	char* ptr() { return reinterpret_cast<char*>(addr_); }
	const char* ptr() const { return reinterpret_cast<char*>(addr_); }

private:
	Process* proc_;
	uint64_t addr_;
};

template <class T>
std::optional<T> Address::ReadValue(uint64_t addr) const
{
	T tmp;
	if (!Read(&tmp, sizeof(T)))
		return std::nullopt;
	return tmp;
}
}
