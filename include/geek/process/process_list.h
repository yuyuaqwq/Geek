#pragma once
#include <Windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string_view>

namespace geek {
class ProcessList;

class ProcessListNode {
public:
	using iterator_category = std::bidirectional_iterator_tag;

	ProcessListNode(ProcessList* owner, const std::vector<PROCESSENTRY32W>::iterator& it);

	bool IsEnd() const;

	uint32_t ProcessId() const;
	uint32_t ParentProcessId() const;
	std::wstring_view ProcessName() const;

	ProcessListNode& operator++();
	ProcessListNode operator++(int);
	ProcessListNode& operator--();
	ProcessListNode operator--(int);

	ProcessListNode& operator*() { return *this; }
	ProcessListNode& operator->() { return *this; }

	bool operator==(const ProcessListNode& right) const;
	bool operator!=(const ProcessListNode& right) const;

private:
	ProcessList* owner_;
	std::vector<PROCESSENTRY32W>::iterator it_;
};

class ProcessList {
public:
	ProcessList();

	bool IsValid() const;

	ProcessListNode begin() const;
	ProcessListNode end() const;

	ProcessListNode FindFirstByProcName(std::wstring_view name) const;
	std::vector<ProcessListNode> FindAllByProcName(std::wstring_view name) const;

private:
	friend class ProcessListNode;
	std::vector<PROCESSENTRY32W> process_entrys_;
};
}