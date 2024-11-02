#pragma once

namespace geek {
class NonCopyable {
public:
    NonCopyable() = default;
    NonCopyable(const NonCopyable&) = delete;
    NonCopyable& operator=(const NonCopyable&) = delete;
};

class NonMoveable {
public:
    NonMoveable() = default;
    NonMoveable(NonMoveable&&) = delete;
    NonMoveable& operator=(NonMoveable&&) = delete;
};

class NonCopyMoveable : public NonCopyable, public NonMoveable
{
public:
    NonCopyMoveable() = default;
};
}
