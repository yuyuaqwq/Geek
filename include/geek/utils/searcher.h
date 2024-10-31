#pragma once
#include <vector>
#include <string>

namespace geek {
class Searcher {
public:
	static std::vector<size_t> SearchHex(
		std::string_view hex,
		const char* data,
		size_t data_size);

	static std::vector<size_t> SearchEx(
		std::string_view pattern,
		const char* data,
		size_t data_size,
		size_t max_match_size = static_cast<size_t>(-1));
};
}
