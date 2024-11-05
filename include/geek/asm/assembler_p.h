#pragma once
#include <type_traits>

#include <geek/global.h>
#include <geek/asm/regs.h>

namespace geek {
namespace internal {
class Imm {
public:
	template<class T>
	static constexpr bool IsConstexprConstructible = std::is_integral_v<T>
												  || std::is_enum_v<T>
												  || std::is_pointer_v<T>
												  || std::is_function_v<T>;

	template<class T, class = typename std::enable_if_t<IsConstexprConstructible<std::decay_t<T>>>>
	constexpr Imm(const T& val) noexcept {
		data_.u64 = static_cast<uint64_t>(val);
		index_ = 0;
	}

	Imm(const float& f) noexcept { data_.f = f; index_ = 1; }
	Imm(const double& d) noexcept { data_.d = d; index_ = 2; }

	bool is_integral() const { return index_ == 0; }
	bool is_float() const { return index_ == 1; }
	bool is_double() const { return index_ == 2; }

	auto integral() const { return data_.u64; }
	auto float_() const { return data_.f; }
	auto double_() const { return data_.d; }

private:
	union 
	{
		uint64_t u64;
		float f;
		double d;
	} data_;
	uint8_t index_;
};

// [Internal] Don't construct directly!
// use geek::asm_ptr
class Mem {
public:
	Mem() = default;
	~Mem();

	Mem(const Mem& right);
	Mem(Mem&& right) noexcept;

	class Impl;
	std::unique_ptr<Impl> impl_;
};
}
}
