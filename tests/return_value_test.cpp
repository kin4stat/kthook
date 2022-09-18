#include "gtest/gtest.h"
#include "kthook/kthook.hpp"
#include "test_common.hpp"

constexpr unsigned char byte_ret = 0x50;
constexpr unsigned short word_ret = 0x5050;
constexpr unsigned long dword_ret = 0x50505050ul;
constexpr unsigned long long qword_ret = 0x5050505050505050ull;

DECLARE_SIZE_ENLARGER();


struct Bool {
    NO_OPTIMIZE static bool CCONV
    test_func(int value) {
        SIZE_ENLARGER()
        return value;
    }
};


struct Byte {
    NO_OPTIMIZE static unsigned char CCONV
    test_func(int value) {
        SIZE_ENLARGER()
        return value;
    }
};

struct Word {
    NO_OPTIMIZE static unsigned short CCONV
    test_func(int value) {
        SIZE_ENLARGER()
        return value;
    }
};

struct Dword {
    NO_OPTIMIZE static unsigned long CCONV
    test_func(int value) {
        SIZE_ENLARGER()
        return value;
    }
};

struct Qword {
    NO_OPTIMIZE static unsigned long long CCONV
    test_func(int value) {
        SIZE_ENLARGER()
        return value;
    }
};

struct NonTriviallyConstructible {
    NonTriviallyConstructible() {
        v = 10;
    }

    explicit NonTriviallyConstructible(int v)
        : v(v) {
    }

    NO_OPTIMIZE static NonTriviallyConstructible CCONV
    test_func(int value) {
        SIZE_ENLARGER()
        return {};
    }

    friend bool operator==(const NonTriviallyConstructible& lhs, const NonTriviallyConstructible& rhs) {
        return lhs.v == rhs.v;
    }

    int v;
};

struct NonTriviallyCopyable {
    NonTriviallyCopyable() = default;
    NonTriviallyCopyable(const NonTriviallyCopyable& rhs) {
        this->v = rhs.v;
    }
    NonTriviallyCopyable(int v)
        : v(v) {
    }

    NO_OPTIMIZE static NonTriviallyCopyable CCONV
    test_func(int value) {
        SIZE_ENLARGER()
        return {};
    }

    friend bool operator==(const NonTriviallyCopyable& lhs, const NonTriviallyCopyable& rhs) {
        return lhs.v == rhs.v;
    }

    int v;
};

struct NonStandardLayout {
    NonStandardLayout() = default;
    explicit NonStandardLayout(int v)
        : v(v) {
    }

    NO_OPTIMIZE static NonStandardLayout CCONV
    test_func(int value) {
        SIZE_ENLARGER();
        return {};
    }

    friend bool operator==(const NonStandardLayout& lhs, const NonStandardLayout& rhs) {
        return lhs.v == rhs.v;
    }

private:
    int v{};
};

TEST(kthook_simple, bool) {
    kthook::kthook_simple<decltype(&Bool::test_func)> hook{&Bool::test_func};
    EXPECT_TRUE(hook.install());

    {
        const auto test_arg = GET_RANDOM_INT();

        hook.set_cb([test_arg](const auto& hook, int& value) {
            EXPECT_EQ(value, test_arg);

            hook.get_trampoline()(value);

            EXPECT_EQ(value, test_arg);
            return true;
        });

        EXPECT_TRUE(Bool::test_func(test_arg));
    }

    {
        const auto test_arg = GET_RANDOM_INT();

        hook.set_cb([test_arg](const auto& hook, int& value) {
            EXPECT_EQ(value, test_arg);

            hook.get_trampoline()(value);

            EXPECT_EQ(value, test_arg);
            return false;
        });

        EXPECT_FALSE(Bool::test_func(test_arg));
    }
}

TEST(kthook_simple, byte) {
    kthook::kthook_simple<decltype(&Byte::test_func)> hook{&Byte::test_func};
    EXPECT_TRUE(hook.install());

    {
        const auto test_arg = GET_RANDOM_INT();
        const auto test_ret = GET_RANDOM_BYTE();

        hook.set_cb([test_arg, test_ret](const auto& hook, int& value) {
            EXPECT_EQ(value, test_arg);

            hook.get_trampoline()(value);

            EXPECT_EQ(value, test_arg);
            return test_ret;
        });

        EXPECT_EQ(Byte::test_func(test_arg), test_ret);
    }
}

TEST(kthook_simple, word) {
    kthook::kthook_simple<decltype(&Word::test_func)> hook{&Word::test_func};
    EXPECT_TRUE(hook.install());

    {
        const auto test_arg = GET_RANDOM_INT();
        const auto test_ret = GET_RANDOM_WORD();

        hook.set_cb([test_arg, test_ret](const auto& hook, int& value) {
            EXPECT_EQ(value, test_arg);

            hook.get_trampoline()(value);

            EXPECT_EQ(value, test_arg);
            return test_ret;
        });

        EXPECT_EQ(Word::test_func(test_arg), test_ret);
    }
}

TEST(kthook_simple, dword) {
    kthook::kthook_simple<decltype(&Dword::test_func)> hook{&Dword::test_func};
    EXPECT_TRUE(hook.install());

    {
        const auto test_arg = GET_RANDOM_INT();
        const auto test_ret = GET_RANDOM_DWORD();

        hook.set_cb([test_arg, test_ret](const auto& hook, int& value) {
            EXPECT_EQ(value, test_arg);

            hook.get_trampoline()(value);

            EXPECT_EQ(value, test_arg);
            return test_ret;
        });

        EXPECT_EQ(Dword::test_func(test_arg), test_ret);
    }
}

TEST(kthook_simple, qword) {
    kthook::kthook_simple<decltype(&Qword::test_func)> hook{&Qword::test_func};
    EXPECT_TRUE(hook.install());

    {
        const auto test_arg = GET_RANDOM_INT();
        const auto test_ret = GET_RANDOM_QWORD();

        hook.set_cb([test_arg, test_ret](const auto& hook, int& value) {
            EXPECT_EQ(value, test_arg);

            hook.get_trampoline()(value);

            EXPECT_EQ(value, test_arg);
            return test_ret;
        });

        EXPECT_EQ(Qword::test_func(test_arg), test_ret);
    }
}

TEST(kthook_simple, non_trivially_constructible) {
    kthook::kthook_simple<decltype(&NonTriviallyConstructible::test_func)> hook{&NonTriviallyConstructible::test_func};
    EXPECT_TRUE(hook.install());

    {
        const auto test_arg = GET_RANDOM_INT();
        const auto test_ret = NonTriviallyConstructible{GET_RANDOM_INT()};

        hook.set_cb([test_arg, test_ret](const auto& hook, int& value) {
            EXPECT_EQ(value, test_arg);

            hook.get_trampoline()(value);

            EXPECT_EQ(value, test_arg);
            return test_ret;
        });

        EXPECT_EQ(NonTriviallyConstructible::test_func(test_arg), test_ret);
    }
}

TEST(kthook_simple, non_trivially_copyable) {
    kthook::kthook_simple<decltype(&NonTriviallyCopyable::test_func)> hook{&NonTriviallyCopyable::test_func};
    EXPECT_TRUE(hook.install());

    {
        const auto test_arg = GET_RANDOM_INT();
        const auto test_ret = NonTriviallyCopyable{GET_RANDOM_INT()};

        hook.set_cb([test_arg, test_ret](const auto& hook, int& value) {
            EXPECT_EQ(value, test_arg);

            hook.get_trampoline()(value);

            EXPECT_EQ(value, test_arg);
            return test_ret;
        });

        EXPECT_EQ(NonTriviallyCopyable::test_func(test_arg), test_ret);
    }
}

TEST(kthook_simple, non_standard_copyable) {
    kthook::kthook_simple<decltype(&NonStandardLayout::test_func)> hook{&NonStandardLayout::test_func};
    EXPECT_TRUE(hook.install());

    {
        const auto test_arg = GET_RANDOM_INT();
        const auto test_ret = NonStandardLayout{GET_RANDOM_INT()};

        hook.set_cb([test_arg, test_ret](const auto& hook, int& value) {
            EXPECT_EQ(value, test_arg);

            hook.get_trampoline()(value);

            EXPECT_EQ(value, test_arg);
            return test_ret;
        });

        EXPECT_EQ(NonStandardLayout::test_func(test_arg), test_ret);
    }
}

TEST(kthook_signal, bool) {
    kthook::kthook_signal<decltype(&Bool::test_func)> hook{&Bool::test_func, false};
    EXPECT_TRUE(hook.install());

    {
        const auto test_arg = GET_RANDOM_INT();

        auto connection = hook.before.scoped_connect([test_arg](const auto& hook, int& value) {
            EXPECT_EQ(value, test_arg);
            return std::make_optional(true);
        });

        EXPECT_TRUE(Bool::test_func(test_arg));
    }

    {
        const auto test_arg = GET_RANDOM_INT();

        auto connection = hook.before.scoped_connect([test_arg](const auto& hook, int& value) {
            EXPECT_EQ(value, test_arg);
            return std::make_optional(false);
        });

        EXPECT_FALSE(Bool::test_func(test_arg));
    }
}

TEST(kthook_signal, byte) {
    kthook::kthook_signal<decltype(&Byte::test_func)> hook{&Byte::test_func, false};
    EXPECT_TRUE(hook.install());

    {
        const auto test_arg = GET_RANDOM_INT();
        const auto test_ret = GET_RANDOM_BYTE();

        auto connection = hook.before.scoped_connect([test_arg, test_ret](const auto& hook, int& value) {
            EXPECT_EQ(value, test_arg);
            return std::make_optional(test_ret);
        });

        EXPECT_EQ(Byte::test_func(test_arg), test_ret);
    }
}

TEST(kthook_signal, word) {
    kthook::kthook_signal<decltype(&Word::test_func)> hook{&Word::test_func, false};
    EXPECT_TRUE(hook.install());

    {
        const auto test_arg = GET_RANDOM_INT();
        const auto test_ret = GET_RANDOM_WORD();

        auto connection = hook.before.scoped_connect([test_arg, test_ret](const auto& hook, int& value) {
            EXPECT_EQ(value, test_arg);
            return std::make_optional(test_ret);
        });

        EXPECT_EQ(Word::test_func(test_arg), test_ret);
    }
}

TEST(kthook_signal, dword) {
    kthook::kthook_signal<decltype(&Dword::test_func)> hook{&Dword::test_func, false};
    EXPECT_TRUE(hook.install());

    {
        const auto test_arg = GET_RANDOM_INT();
        const auto test_ret = GET_RANDOM_DWORD();

        auto connection = hook.before.scoped_connect([test_arg, test_ret](const auto& hook, int& value) {
            EXPECT_EQ(value, test_arg);
            return std::make_optional(test_ret);
        });

        EXPECT_EQ(Dword::test_func(test_arg), test_ret);
    }
}

TEST(kthook_signal, qword) {
    kthook::kthook_signal<decltype(&Qword::test_func)> hook{&Qword::test_func, false};
    EXPECT_TRUE(hook.install());
    {
        const auto test_arg = GET_RANDOM_INT();
        const auto test_ret = GET_RANDOM_QWORD();

        auto connection = hook.before.scoped_connect([test_arg, test_ret](const auto& hook, int& value) {
            EXPECT_EQ(value, test_arg);
            return std::make_optional(test_ret);
        });

        EXPECT_EQ(Qword::test_func(test_arg), test_ret);
    }
}

TEST(kthook_signal, non_trivially_constructible) {
    kthook::kthook_signal<decltype(&NonTriviallyConstructible::test_func)> hook{&NonTriviallyConstructible::test_func, false};
    EXPECT_TRUE(hook.install());

    {
        const auto test_arg = GET_RANDOM_INT();
        const auto test_ret = NonTriviallyConstructible{GET_RANDOM_INT()};

        auto connection = hook.before.scoped_connect([test_arg, test_ret](const auto& hook, int& value) {
            EXPECT_EQ(value, test_arg);
            return std::make_optional(test_ret);
        });

        EXPECT_EQ(NonTriviallyConstructible::test_func(test_arg), test_ret);
    }
}

TEST(kthook_signal, non_trivially_copyable) {
    kthook::kthook_signal<decltype(&NonTriviallyCopyable::test_func)> hook{&NonTriviallyCopyable::test_func, false};
    EXPECT_TRUE(hook.install());

    {
        const auto test_arg = GET_RANDOM_INT();
        const auto test_ret = NonTriviallyCopyable{GET_RANDOM_INT()};

        auto connection = hook.before.scoped_connect([test_arg, test_ret](const auto& hook, int& value) {
            EXPECT_EQ(value, test_arg);
            return std::make_optional(test_ret);
        });

        EXPECT_EQ(NonTriviallyCopyable::test_func(test_arg), test_ret);
    }
}

TEST(kthook_signal, non_standard_layout) {
    kthook::kthook_signal<decltype(&NonStandardLayout::test_func)> hook{&NonStandardLayout::test_func, false};
    EXPECT_TRUE(hook.install());

    {
        const auto test_arg = GET_RANDOM_INT();
        const auto test_ret = NonStandardLayout{GET_RANDOM_INT()};

        auto connection = hook.before.scoped_connect([test_arg, test_ret](const auto& hook, int& value) {
            EXPECT_EQ(value, test_arg);
            return std::make_optional(test_ret);
        });

        EXPECT_EQ(NonStandardLayout::test_func(test_arg), test_ret);
    }
}
