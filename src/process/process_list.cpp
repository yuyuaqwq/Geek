#include <geek/process/process_list.h>
#include <psapi.h>

#include "errordefs.h"
#include <geek/utils/handle.h>
#include <geek/utils/strutil.h>

namespace geek {
ProcessList::ProcessList()
{
	auto h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (h == INVALID_HANDLE_VALUE)
	{
		GEEK_UPDATE_WIN_ERROR();
		return;
	}

	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32W);

	if (Process32FirstW(h, &pe32)) {
		do {
			process_entrys_.push_back(pe32);
		} while (Process32NextW(h, &pe32));
	}
	else {
		GEEK_UPDATE_WIN_ERROR();
	}
	CloseHandle(h);
}

bool ProcessList::IsValid() const
{
	return process_entrys_.empty();
}

ProcessListNode ProcessList::begin() const
{
	return { const_cast<ProcessList*>(this), const_cast<std::vector<PROCESSENTRY32W>&>(process_entrys_).begin() };
}

ProcessListNode ProcessList::end() const
{
	return { const_cast<ProcessList*>(this), const_cast<std::vector<PROCESSENTRY32W>&>(process_entrys_).end() };
}

ProcessListNode ProcessList::FindFirstByProcName(std::wstring_view name) const
{
	auto n = StrUtil::ToUppercase(name);
	for (auto& p : *this)
	{
		auto n2 = StrUtil::ToUppercase(p.ProcessName());
		if (n == n2)
			return p;
	}
	return end();
}

std::vector<ProcessListNode> ProcessList::FindAllByProcName(std::wstring_view name) const
{
	std::vector<ProcessListNode> total;
	auto n = StrUtil::ToUppercase(name);
	for (auto& p : *this)
	{
		auto n2 = StrUtil::ToUppercase(p.ProcessName());
		if (n == n2)
			total.push_back(p);
	}
	return total;
}

ProcessListNode::ProcessListNode(ProcessList* owner, const std::vector<PROCESSENTRY32W>::iterator& it)
	: owner_(owner), it_(it)
{
}

bool ProcessListNode::IsEnd() const
{
	return it_ == owner_->process_entrys_.end();
}

uint32_t ProcessListNode::ProcessId() const
{
	return it_->th32ProcessID;
}

uint32_t ProcessListNode::ParentProcessId() const
{
	return it_->th32ParentProcessID;
}

std::wstring_view ProcessListNode::ProcessName() const
{
	return it_->szExeFile;
}

ProcessListNode& ProcessListNode::operator++()
{
	++it_;
	return *this;
}

ProcessListNode ProcessListNode::operator++(int)
{
	auto tmp = *this;
	++*this;
	return tmp;
}

ProcessListNode& ProcessListNode::operator--()
{
	--it_;
	return *this;
}

ProcessListNode ProcessListNode::operator--(int)
{
	auto tmp = *this;
	--*this;
	return tmp;
}

bool ProcessListNode::operator==(const ProcessListNode& right) const
{
	return owner_ == right.owner_ && it_ == right.it_;
}

bool ProcessListNode::operator!=(const ProcessListNode& right) const
{
	return !operator==(right);
}
}
