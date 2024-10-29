#pragma once
#include <vector>
#include <string>

namespace geek {
class Searcher {
public:
	template<size_t kSize, class Elem1, class Elem2>
	static std::vector<size_t> SearchMemory(
		const Elem1 (&pattern)[kSize],
		const Elem2* data,
		size_t data_size,
		size_t max_match_size = static_cast<size_t>(-1));

	template<class Elem1, class Elem2>
	static std::vector<size_t> SearchMemory(
		const Elem1* pattern,
		size_t pattern_size,
		const Elem2* data,
		size_t data_size,
		size_t max_match_size = static_cast<size_t>(-1));

private:
	static std::vector<size_t> SearchMemory2(
		const char* pattern,
		size_t pattern_size,
		const char* data,
		size_t data_size,
		size_t max_match_size = static_cast<size_t>(-1));
};

template <size_t kSize, class Elem1, class Elem2>
std::vector<size_t> Searcher::SearchMemory(const Elem1(& pattern)[kSize], const Elem2* data, size_t data_size,
	size_t max_match_size)
{
	static_assert(sizeof(Elem1) == 1 && sizeof(Elem2) == 1);
	return SearchMemory(reinterpret_cast<const Elem1*>(pattern), kSize, data, data_size);
}

template <class Elem1, class Elem2>
std::vector<size_t> Searcher::SearchMemory(const Elem1* pattern, size_t pattern_size, const Elem2* data,
	size_t data_size, size_t max_match_size)
{
	static_assert(sizeof(Elem1) == 1 && sizeof(Elem2) == 1);
	return SearchMemory2(reinterpret_cast<const char*>(pattern), pattern_size, reinterpret_cast<const char*>(data), data_size, max_match_size);
}
}
