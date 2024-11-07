#pragma once
#include <cstdint>

namespace geek {
class Process;

class ListEntry {
public:
	ListEntry() = default;
	ListEntry(Process* proc, uint64_t addr);

	bool IsValid() const;
	uint64_t addr() const { return addr_; }
	ListEntry Flink() const;
	ListEntry Blink() const;

	bool operator==(const ListEntry& right) const { return proc_ == right.proc_ && addr_ == right.addr_; }

	template<class T>
	T* ToObject() const {
		return reinterpret_cast<T*>(addr_);
	}

private:
	Process* proc_ = nullptr;
	uint64_t addr_ = 0;
	uint64_t flink_ = 0;
	uint64_t blink_ = 0;
};
}