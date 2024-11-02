#include <geek/utils/searcher.h>
#include <regex>

namespace geek {
std::vector<size_t> Searcher::SearchHex(std::string_view hex, const char* data, size_t data_size)
{
	std::string h{ hex };
	// �Ƴ��ո�
	h.erase(std::remove(h.begin(), h.end(), ' '), h.end());

	// �������ż����ͷ����һ���ֽ�
	if (h.size() % 2 != 0)
	{
		h.insert(0, "0");
	}

	std::vector<char> pattern;
	auto bytes_count = h.size() / 2;
	for (size_t i = 0; i < bytes_count; ++i)
	{
		pattern.push_back('\\');
		pattern.push_back('x');
		pattern.push_back(h[i * 2]);
		pattern.push_back(h[i * 2 + 1]);
	}
	// ��β��Ҫ��.*ƥ��
	pattern.push_back('.');
	pattern.push_back('*');

	return SearchEx({ pattern.data(), pattern.size() }, data, data_size, bytes_count);
}

std::vector<size_t> Searcher::SearchEx(std::string_view pattern, const char* data,
	                                       size_t data_size, size_t max_match_size)
{
	std::regex r(pattern.data(), pattern.size());
	std::cmatch m;
	std::vector<size_t> total;

	auto seek = data;
	while (std::regex_search(seek, data + data_size, m, r))
	{
		seek += m.position();
		total.push_back(seek - data);
		seek += std::min(static_cast<size_t>(m.length()), max_match_size);
	}
	return total;
}
}