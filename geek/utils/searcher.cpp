#include <geek/utils/searcher.h>
#include <regex>

namespace geek {
std::vector<size_t> Searcher::SearchMemory2(const char* pattern, size_t pattern_size, const char* data,
	size_t data_size, size_t max_match_size)
{
	std::regex r(pattern, pattern + pattern_size);
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